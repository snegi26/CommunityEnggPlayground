from fastapi.testclient import TestClient

from passport.app import create_app


def test_healthz_reports_database_connectivity(database_urls: dict[str, str]) -> None:
    client = TestClient(create_app())

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}
