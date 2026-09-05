import time

from conftest import make_jwt


def test_valid_token_accepted(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "exp": int(time.time()) + 600})
    r = client.get("/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and r.json() == {"sub": "alice"}

def test_none_alg_rejected(client):
    tok = make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "attacker", "exp": int(time.time()) + 600}, alg="none")
    r = client.get("/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401, "alg=none bypass still works"

def test_hs512_alg_confusion_rejected(client):
    tok = make_jwt({"alg": "HS512", "typ": "JWT"}, {"sub": "attacker", "exp": int(time.time()) + 600}, alg="HS512")
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_expired_token_rejected(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "exp": int(time.time()) - 10})
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_missing_exp_rejected(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice"})
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_non_numeric_exp_rejected(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "exp": "soon"})
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_old_hardcoded_secret_signature_rejected(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "attacker", "exp": int(time.time()) + 600},
                   secret="dev-secret-123")
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_login_flow_still_works(client):
    r = client.post("/login", json={"username": "alice", "password": "pw-alice"})
    assert r.status_code == 200
    me = client.get("/me", headers={"Authorization": f"Bearer {r.json()['token']}"})
    assert me.status_code == 200 and me.json() == {"sub": "alice"}
