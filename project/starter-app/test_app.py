import os
import tempfile

import pytest

import app


@pytest.fixture()
def client(monkeypatch):
    with tempfile.NamedTemporaryFile(delete=False) as database:
        path = database.name
    monkeypatch.setattr(app, "DB", path)
    app.seed()
    with app.app.test_client() as test_client:
        yield test_client
    os.unlink(path)


def csrf(client):
    response = client.get("/")
    return response, client.get_cookie("csrf_token").value


def login(client, username="alice", password="alicepw"):
    _, token = csrf(client)
    return client.post("/login", data={
        "username": username, "password": password, "csrf_token": token
    })


def test_login_rejects_sql_injection(client):
    _, token = csrf(client)
    response = client.post("/login", data={
        "username": "' OR '1'='1", "password": "nope", "csrf_token": token
    })
    assert response.status_code == 401


def test_search_is_parameterized_and_escaped(client):
    assert login(client).status_code == 302
    response = client.post("/notes", data={
        "title": "<script>alert(1)</script>",
        "body": "<img src=x onerror=alert(1)>",
        "csrf_token": client.get_cookie("csrf_token").value,
    })
    assert response.status_code == 302
    response = client.get("/search?q=%27%20OR%201%3D1%20--")
    assert response.status_code == 200
    assert b"<script>" not in response.data
    assert b"&lt;script&gt;" in client.get("/").data


def test_api_note_enforces_ownership(client):
    assert login(client).status_code == 302
    assert client.get("/api/notes/2").status_code == 404


def test_registration_cannot_select_admin_role(client):
    _, token = csrf(client)
    response = client.post("/register", data={
        "username": "new-user", "password": "long-enough-password",
        "role": "admin", "csrf_token": token,
    })
    assert response.status_code == 302
    con = app.db()
    assert con.execute(
        "SELECT role FROM users WHERE username = 'new-user'"
    ).fetchone()["role"] == "user"
    con.close()


def test_export_rejects_command_payload_and_scopes_data(client):
    assert login(client).status_code == 302
    response = client.get("/export?fmt=txt%3Bcat%20%2Fetc%2Fpasswd")
    assert response.status_code == 400
    assert b"hunter2" not in client.get("/export?fmt=txt").data


def test_admin_does_not_expose_password_hashes(client):
    assert login(client, "admin", "admin123").status_code == 302
    response = client.get("/admin")
    assert response.status_code == 200
    assert b"password" not in response.data


def test_state_changing_request_requires_csrf(client):
    response = client.post("/login", data={"username": "alice", "password": "alicepw"})
    assert response.status_code == 403
