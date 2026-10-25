import re

import pytest
from app import db
from tests.conftest import Client


def test_every_route_requires_login_or_is_allowlisted(app):
    from app.auth import PUBLIC
    c = app.test_client()
    for rule in app.url_map.iter_rules():
        if rule.endpoint in PUBLIC:
            continue
        url = re.sub(r"<[^>]+>", "1", rule.rule)
        for m in rule.methods - {"HEAD", "OPTIONS"}:
            r = c.open(url, method=m, base_url="https://localhost")
            assert r.status_code == 302 and "/login" in r.headers["Location"], (rule.rule, m)


def test_public_allowlist_is_exactly_login_health_static(app):
    from app.auth import PUBLIC
    assert PUBLIC == {
        "auth.login_form", "auth.login_submit",
        "auth.login_mfa", "auth.login_mfa_submit",
        "auth.register", "auth.register_submit",
        "auth.forgot_password", "auth.forgot_password_submit",
        "auth.reset_password", "auth.reset_password_submit",
        "healthz", "static",
    }


def test_post_without_csrf_token_is_rejected(alice, doc):
    assert alice.post(f"/documents/{doc}/delete", csrf=False).status_code == 400
    assert alice.get(f"/documents/{doc}/download").status_code == 200       # not deleted


def test_logout_kills_the_session(alice):
    assert alice.get("/documents").status_code == 200
    alice.post("/logout")
    assert alice.get("/documents").status_code == 302


def test_disabled_user_session_dies_immediately(app, bob, admin):
    assert bob.get("/documents").status_code == 200
    assert admin.post(f"/admin/users/{bob.id}/disable").status_code == 302
    assert bob.get("/documents").status_code == 302
    assert bob.login().status_code == 401


def test_session_cookie_flags(app, alice):
    r = alice.c.get("/login", base_url=alice.base)
    page = r.get_data(as_text=True)
    resp = app.test_client().post("/login", base_url="https://localhost", data={
        "login_token": re.search(r'name="login_token" value="([^"]+)"', page).group(1),
        "email": alice.email, "password": alice.password})
    cookie = resp.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie


def test_lockout_after_repeated_failures(app, alice):
    bad = Client(app, alice.email, "wrong-password")
    for _ in range(5):
        assert bad.login().status_code == 401
    assert alice.login().status_code == 401          # correct password, but the account is locked
    with app.app_context():
        db.run("UPDATE users SET locked_until=NULL, failed_logins=0 WHERE id=%s", (alice.id,))
        db.conn().commit()


def test_login_without_valid_token_is_refused(app):
    r = app.test_client().post("/login", base_url="https://localhost",
                                data={"login_token": "forged", "email": "a@b.c", "password": "x"})
    assert r.status_code == 400


def test_security_headers(alice):
    r = alice.get("/documents")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_change_password_invalidates_other_sessions(app, alice):
    second = Client(app, alice.email, alice.password)
    assert second.login().status_code == 302
    assert second.get("/documents").status_code == 200
    assert alice.get("/documents").status_code == 200

    new_pw = "NewSecretPass123!"
    r = alice.post("/change-password", data={
        "current_password": alice.password,
        "new_password": new_pw,
        "confirm_password": new_pw
    })
    assert r.status_code == 200
    assert "Your password has been changed" in r.get_data(as_text=True)

    assert alice.get("/documents").status_code == 200
    assert second.get("/documents").status_code == 302

    alice.password = new_pw
    assert alice.login().status_code == 302


def test_change_password_rejects_wrong_current_password(alice):
    r = alice.post("/change-password", data={
        "current_password": "WrongPassword123!",
        "new_password": "NewSecretPass123!",
        "confirm_password": "NewSecretPass123!"
    })
    assert r.status_code == 400
    assert "Current password is incorrect" in r.get_data(as_text=True)


def test_reset_password_purges_all_sessions(app, alice):
    from app.routes.auth_routes import _form_token, _generate_reset_token

    # Create a second session
    second = Client(app, alice.email, alice.password)
    assert second.login().status_code == 302
    assert second.get("/documents").status_code == 200
    assert alice.get("/documents").status_code == 200

    # Obtain current password hash and generate valid token
    with app.app_context():
        u = db.one("SELECT id, password_hash FROM users WHERE id = %s", (alice.id,))
        token = _generate_reset_token(u["id"], u["password_hash"])
        login_tok = _form_token()

    c = app.test_client()
    new_pw = "ResetPassBrandNew123!"
    r = c.post(f"/reset-password/{token}", data={
        "login_token": login_tok,
        "password": new_pw,
        "confirm_password": new_pw,
    }, base_url=alice.base)
    assert r.status_code == 200
    assert "Your password has been successfully reset" in r.get_data(as_text=True)

    # Both old sessions MUST be dead
    assert alice.get("/documents").status_code == 302
    assert second.get("/documents").status_code == 302

    # New login works with new password
    alice.password = new_pw
    assert alice.login().status_code == 302
