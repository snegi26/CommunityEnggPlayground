"""Drafting eval (U9): precision and recall per predicate against a hand-labeled gold set.

The live test is marked ``eval`` (deselected by default) and skips without an
``ANTHROPIC_API_KEY``. Run it with::

    ANTHROPIC_API_KEY=... uv run pytest -m eval -s tests/eval

Each ``gold/*.md`` policy has a ``gold/*.json`` listing the checkable claims a careful
reviewer expects: a predicate id and the parameters that matter. A drafted claim matches an
expected one when the predicate is the same and every listed parameter is equal; extra
drafted parameters are not compared. Not-checkable claims are not scored. Thresholds live
in ``gold/eval_config.json``. Set ``PASSPORT_EVAL_REPORT`` to a path to also write the report
as JSON.
"""

import json
import os
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

import passport.predicates.definitions  # noqa: F401  (registers v1 predicates)
from passport.agent.client import AnthropicModelClient, drafting_model
from passport.agent.drafting import DraftOutcome, draft_spans
from passport.agent.tools import InMemorySpans, SpanText
from passport.documents.parsing import parse_document
from passport.predicates.registry import registry

GOLD = Path(__file__).parent / "gold"
CONFIG = json.loads((GOLD / "eval_config.json").read_text())

Expected = Mapping[str, Any]  # {"predicate": str, "params": {...}}


def gold_cases() -> list[tuple[str, bytes, list[Expected]]]:
    cases = []
    for policy in sorted(GOLD.glob("*.md")):
        expected = json.loads(policy.with_suffix(".json").read_text())["claims"]
        cases.append((policy.name, policy.read_bytes(), expected))
    return cases


@dataclass
class Score:
    tp: Counter[str] = field(default_factory=Counter)
    fp: Counter[str] = field(default_factory=Counter)
    fn: Counter[str] = field(default_factory=Counter)

    def add(self, predicted: Iterable[Expected], expected: Sequence[Expected]) -> None:
        unmatched = list(expected)
        seen: set[str] = set()
        for claim in predicted:
            key = json.dumps([claim["predicate"], claim["params"]], sort_keys=True)
            if key in seen:  # The same check drafted from two sentences counts once.
                continue
            seen.add(key)
            match = next((e for e in unmatched if _matches(claim, e)), None)
            if match is None:
                self.fp[claim["predicate"]] += 1
            else:
                unmatched.remove(match)
                self.tp[claim["predicate"]] += 1
        for missed in unmatched:
            self.fn[missed["predicate"]] += 1

    def precision(self, predicate: str | None = None) -> float:
        tp, fp = self._counts(predicate, self.tp), self._counts(predicate, self.fp)
        return tp / (tp + fp) if tp + fp else 1.0

    def recall(self, predicate: str | None = None) -> float:
        tp, fn = self._counts(predicate, self.tp), self._counts(predicate, self.fn)
        return tp / (tp + fn) if tp + fn else 1.0

    def support(self, predicate: str) -> int:
        return self.tp[predicate] + self.fn[predicate]

    @staticmethod
    def _counts(predicate: str | None, counter: Counter[str]) -> int:
        return counter[predicate] if predicate else sum(counter.values())

    def predicates(self) -> list[str]:
        return sorted(set(self.tp) | set(self.fp) | set(self.fn))

    def report(self) -> dict[str, Any]:
        return {
            "overall": {"precision": self.precision(), "recall": self.recall()},
            "per_predicate": {
                p: {
                    "precision": self.precision(p),
                    "recall": self.recall(p),
                    "tp": self.tp[p],
                    "fp": self.fp[p],
                    "fn": self.fn[p],
                }
                for p in self.predicates()
            },
        }

    def failures(self, config: Mapping[str, Any]) -> list[str]:
        """Every threshold in ``config`` the score falls below, as readable lines."""
        failures = []
        overall = config["overall"]
        if self.precision() < overall["precision"]:
            failures.append(f"overall precision {self.precision():.2f} < {overall['precision']}")
        if self.recall() < overall["recall"]:
            failures.append(f"overall recall {self.recall():.2f} < {overall['recall']}")
        per = config["per_predicate"]
        for p in self.predicates():
            if self.support(p) < per["min_support"]:
                continue
            if self.precision(p) < per["precision"]:
                failures.append(f"{p} precision {self.precision(p):.2f} < {per['precision']}")
            if self.recall(p) < per["recall"]:
                failures.append(f"{p} recall {self.recall(p):.2f} < {per['recall']}")
        return failures


def _matches(claim: Expected, expected: Expected) -> bool:
    if claim["predicate"] != expected["predicate"]:
        return False
    return all(claim["params"].get(k) == v for k, v in expected["params"].items())


def _table(report: Mapping[str, Any]) -> str:
    lines = [f"{'predicate':32} {'P':>5} {'R':>5} {'tp':>3} {'fp':>3} {'fn':>3}"]
    for p, row in report["per_predicate"].items():
        lines.append(
            f"{p:32} {row['precision']:5.2f} {row['recall']:5.2f}"
            f" {row['tp']:3} {row['fp']:3} {row['fn']:3}"
        )
    o = report["overall"]
    lines.append(f"{'overall':32} {o['precision']:5.2f} {o['recall']:5.2f}")
    return "\n".join(lines)


# --- Always-on checks of the gold set and scorer (no model) ----------------------


def test_gold_set_has_10_to_15_policies_with_valid_expectations() -> None:
    cases = gold_cases()
    assert 10 <= len(cases) <= 15
    for name, data, expected in cases:
        assert parse_document(name, data).spans, name
        for item in expected:
            predicate = registry.latest(item["predicate"])
            fields = set(predicate.params_model.model_fields)
            assert set(item["params"]) <= fields, (name, item)
            if "scope" in item["params"]:
                predicate.parse_params(item["params"])


def test_scorer_reports_per_predicate_and_fails_below_thresholds() -> None:
    score = Score()
    score.add(
        [
            {"predicate": "mfa_enforced", "params": {"scope": "all_users"}},
            {
                "predicate": "password_min_length",
                "params": {"scope": "all_accounts", "min_length": 8},
            },
        ],
        [
            {"predicate": "mfa_enforced", "params": {"scope": "all_users"}},
            {"predicate": "password_min_length", "params": {"min_length": 14}},
        ],
    )
    report = score.report()
    assert report["per_predicate"]["mfa_enforced"]["precision"] == 1.0
    assert report["per_predicate"]["password_min_length"]["recall"] == 0.0
    assert score.failures(CONFIG)  # 0.5 overall is below the configured bar.

    perfect = Score()
    perfect.add(
        [{"predicate": "mfa_enforced", "params": {"scope": "all_users"}}],
        [{"predicate": "mfa_enforced", "params": {"scope": "all_users"}}],
    )
    assert perfect.failures(CONFIG) == []


# --- The live eval ---------------------------------------------------------------


def _predicted(outcome: DraftOutcome) -> list[Expected]:
    return [
        {"predicate": d.predicate_id, "params": d.parameters}
        for d in outcome.drafts
        if d.predicate_id is not None
    ]


@pytest.mark.eval
@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="needs ANTHROPIC_API_KEY")
def test_drafting_meets_precision_and_recall_thresholds_on_the_gold_set() -> None:
    client = AnthropicModelClient()
    model = drafting_model()
    score = Score()
    counts: Counter[str] = Counter()
    per_policy = {}
    for name, data, expected in gold_cases():
        parsed = parse_document(name, data)
        spans = [SpanText(s.span_id, tuple(s.section_path), s.text) for s in parsed.spans]
        outcome = draft_spans(client, model=model, spans=spans, source=InMemorySpans(spans))
        predicted = _predicted(outcome)
        score.add(predicted, expected)
        counts.update(outcome.counts())
        per_policy[name] = {"predicted": predicted, "counts": outcome.counts()}

    report = {"model": model, **score.report(), "counts": dict(counts), "policies": per_policy}
    print(f"\nDrafting eval on {model}\n{_table(report)}\ncounts: {dict(counts)}")
    if path := os.environ.get("PASSPORT_EVAL_REPORT"):
        Path(path).write_text(json.dumps(report, indent=2, default=str))
    failures = score.failures(CONFIG)
    assert not failures, "below eval thresholds:\n" + "\n".join(failures)
