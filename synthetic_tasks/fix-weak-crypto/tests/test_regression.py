"""Hidden copy of the visible regression suite.

Runs against the verifier's freshly recreated database, so the register
assertion is strict (unlike the agent-visible copy, which tolerates re-runs
against a persistent SQLite file).
"""


def test_register_login_me(client):
    r = client.post("/register", json={"email": "dave@example.com", "password": "DavePass1!"})
    assert r.status_code in (200, 201), r.text
    r = client.post("/login", json={"email": "dave@example.com", "password": "DavePass1!"})
    assert r.status_code == 200, r.text
    me = client.get("/me", headers={"Authorization": f"Bearer {r.json()['token']}"})
    assert me.status_code == 200, me.text
    assert me.json() == {"email": "dave@example.com"}


def test_wrong_password_rejected(client):
    r = client.post("/login", json={"email": "dave@example.com", "password": "WrongPass!"})
    assert r.status_code == 401
