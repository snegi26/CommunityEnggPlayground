"""The connector interface is read-only, and fakes can script every state AE1-AE8 need."""

import inspect
from datetime import UTC, datetime

import pytest

from passport.connectors.base import Capability, Connector, UnsupportedCapabilityError, collect
from passport.connectors.fakes import FakeConnector, users_mfa
from passport.connectors.models import ConnectionKind
from passport.connectors.observation import Failure, Observed
from passport.connectors.registry import ConnectorRegistry, RegistryError, kinds_serving

# Attributes every connector carries that are data, not calls to the provider.
DATA_ATTRIBUTES = {"kind", "collector_version", "scope"}


def _public_members(cls: type) -> set[str]:
    return {name for name in dir(cls) if not name.startswith("_")}


def test_the_connector_interface_exposes_only_capability_named_read_methods() -> None:
    members = _public_members(Connector)
    callables = {m for m in members if callable(getattr(Connector, m))}

    assert callables == {c.value for c in Capability}
    assert members - callables <= DATA_ATTRIBUTES
    for name in callables:
        assert name.startswith(("list_", "get_")), name


def test_capability_methods_take_no_arguments_that_could_carry_a_request() -> None:
    for capability in Capability:
        params = inspect.signature(getattr(Connector, capability.value)).parameters
        assert list(params) == ["self"], capability


def test_an_unserved_capability_raises_rather_than_returning_an_empty_result() -> None:
    connector = FakeConnector(ConnectionKind.GITHUB, scope=("acme",))
    with pytest.raises(UnsupportedCapabilityError):
        connector.get_root_mfa()


def test_registry_declares_capabilities_per_kind() -> None:
    assert set(kinds_serving(Capability.LIST_USERS_MFA)) == {
        ConnectionKind.AWS,
        ConnectionKind.GOOGLE_WORKSPACE,
    }
    assert set(kinds_serving(Capability.GET_BRANCH_PROTECTION)) == {ConnectionKind.GITHUB}
    for capability in Capability:
        assert kinds_serving(capability), f"{capability} served by no connection kind"


def test_registering_a_class_that_misses_a_declared_capability_is_refused() -> None:
    class HalfGithub(Connector):
        kind = ConnectionKind.GITHUB
        collector_version = "half-1"

        def get_branch_protection(self) -> Observed | Failure:
            raise NotImplementedError

    registry = ConnectorRegistry()
    with pytest.raises(RegistryError, match="get_org_two_factor_requirement"):
        registry.register(HalfGithub)


def test_registering_and_looking_up_a_connector_class_by_kind() -> None:
    class FullGoogle(Connector):
        kind = ConnectionKind.GOOGLE_WORKSPACE
        collector_version = "google-1"

        def list_users_mfa(self) -> Observed | Failure:
            raise NotImplementedError

    registry = ConnectorRegistry()
    registry.register(FullGoogle)
    assert registry.connector_class(ConnectionKind.GOOGLE_WORKSPACE) is FullGoogle
    with pytest.raises(RegistryError):
        registry.connector_class(ConnectionKind.AWS)
    with pytest.raises(RegistryError, match="already"):
        registry.register(FullGoogle)


# --- Fakes reproduce the states AE1-AE8 need -------------------------------------------


def test_fake_reports_users_with_and_without_mfa_naming_each_account() -> None:  # AE1, AE2
    fake = FakeConnector(
        ConnectionKind.AWS,
        scope=("111111111111",),
        responses={Capability.LIST_USERS_MFA: users_mfa({"alice": True, "bob": False})},
    )
    result = fake.list_users_mfa()
    assert isinstance(result, Observed)
    assert result.rows == [{"user": "alice", "mfa": True}, {"user": "bob", "mfa": False}]
    assert result.complete and result.checkable
    assert result.scope == ("111111111111",)
    assert result.collector_version == "fake-1"
    assert result.collected_at.tzinfo == UTC


def test_fake_scripts_successive_states_for_a_resolved_item() -> None:  # AE8
    fake = FakeConnector(ConnectionKind.AWS, scope=("111111111111",))
    fake.script(
        Capability.LIST_USERS_MFA,
        users_mfa({"bob": False}),
        users_mfa({"bob": True}),
    )
    first, second = fake.list_users_mfa(), fake.list_users_mfa()
    assert isinstance(first, Observed) and isinstance(second, Observed)
    assert first.rows == [{"user": "bob", "mfa": False}]
    assert second.rows == [{"user": "bob", "mfa": True}]
    # The last scripted state repeats once the script is exhausted.
    third = fake.list_users_mfa()
    assert isinstance(third, Observed) and third.rows == second.rows


def test_fake_refuses_capabilities_its_kind_does_not_serve() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        FakeConnector(
            ConnectionKind.GITHUB,
            scope=("acme",),
            responses={Capability.GET_ROOT_MFA: [{"root_mfa": True}]},
        )


def test_fake_records_which_capabilities_were_read() -> None:
    fake = FakeConnector(
        ConnectionKind.GITHUB,
        scope=("acme",),
        responses={Capability.GET_ORG_TWO_FACTOR_REQUIREMENT: [{"org": "acme", "required": False}]},
    )
    collect(fake, Capability.GET_ORG_TWO_FACTOR_REQUIREMENT)
    assert fake.calls == [Capability.GET_ORG_TWO_FACTOR_REQUIREMENT]


def test_fake_with_a_fixed_clock() -> None:
    at = datetime(2026, 10, 26, 6, tzinfo=UTC)
    fake = FakeConnector(
        ConnectionKind.AWS,
        scope=("111111111111",),
        responses={Capability.GET_PASSWORD_POLICY: [{"minimum_length": 14}]},
        clock=lambda: at,
    )
    result = fake.get_password_policy()
    assert isinstance(result, Observed) and result.collected_at == at


def test_collect_dispatches_by_capability_name() -> None:
    fake = FakeConnector(
        ConnectionKind.AWS,
        scope=("111111111111",),
        responses={Capability.LIST_CLOUDTRAIL_TRAILS: [{"name": "org-trail", "logging": True}]},
    )
    result = collect(fake, Capability.LIST_CLOUDTRAIL_TRAILS)
    assert isinstance(result, Observed) and result.capability is Capability.LIST_CLOUDTRAIL_TRAILS
