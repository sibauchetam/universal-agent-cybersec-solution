from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_post_comment_then_list_contains_author():
    r = client.post("/comments", data={"author": "alice", "body": "hello world"})
    assert r.status_code == 200, r.text
    wall = client.get("/comments")
    assert wall.status_code == 200
    assert "alice" in wall.text
    assert "hello world" in wall.text


def test_profile_page_renders_username():
    r = client.get("/profile/bob")
    assert r.status_code == 200
    assert "Profile: bob" in r.text
