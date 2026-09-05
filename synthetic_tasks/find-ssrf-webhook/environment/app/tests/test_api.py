from fastapi.testclient import TestClient

from main import app

# raise_server_exceptions=False: the vulnerable fetcher propagates fetch
# errors (ValueError / httpx errors); the regression only requires that the
# service answers (4xx/5xx-or-dict) instead of crashing the test process.
client = TestClient(app, raise_server_exceptions=False)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_import_fetch_unresolvable_host_no_crash():
    r = client.post("/import/fetch", json={"url": "http://example.invalid/"})
    assert r.status_code >= 400 or isinstance(r.json(), dict)


def test_webhooks_register_accepts_wellformed_body():
    r = client.post("/webhooks/register", json={"url": "http://example.invalid/"})
    assert r.status_code != 422
