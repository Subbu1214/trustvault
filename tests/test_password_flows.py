import time
from unittest.mock import MagicMock, patch
from itsdangerous import URLSafeTimedSerializer
import pytest

from app import create_app
from app.users import validate_password_strength
from app.routes.auth_routes import (
    _form_token,
    _form_token_ok,
    _generate_reset_token,
    _verify_reset_token,
)


@pytest.fixture
def mock_app():
    return create_app({
        "SECRET_KEY": "a" * 32,
        "DATABASE_URL": "postgresql://test:test@localhost:5432/test",
        "STORAGE_BACKEND": "local",
        "LOCAL_STORAGE_DIR": "tmp_store",
        "TESTING": True,
        "COOKIE_SECURE": False,
    })


def test_password_strength_validation():
    # Empty
    ok, err = validate_password_strength("")
    assert not ok and "required" in err

    # Too short (< 12 chars)
    ok, err = validate_password_strength("Short1!")
    assert not ok and "at least 12 characters" in err

    # 12 chars but only letters (no number or symbol)
    ok, err = validate_password_strength("TwelveLettersOnly")
    assert not ok and "numbers or symbols" in err

    # 12 chars but only digits
    ok, err = validate_password_strength("123456789012")
    assert not ok and "numbers or symbols" in err

    # Valid strong password
    ok, err = validate_password_strength("SuperSecret123!")
    assert ok and err is None

    # Valid with space and symbol
    ok, err = validate_password_strength("Correct Horse Battery #1")
    assert ok and err is None


def test_reset_token_generation_and_verification(mock_app):
    with mock_app.app_context():
        user_id = 42
        original_hash = "scrypt:32768:8:1$abcdef123456"

        token = _generate_reset_token(user_id, original_hash)
        assert isinstance(token, str)

        with patch("app.db.one") as mock_one:
            mock_one.return_value = {
                "id": user_id,
                "email": "alice@example.com",
                "password_hash": original_hash,
                "active": True,
            }
            u, err = _verify_reset_token(token)
            assert err is None
            assert u["id"] == user_id


def test_reset_token_tampered_fails(mock_app):
    with mock_app.app_context():
        token = _generate_reset_token(1, "hash123")
        tampered = token[:-4] + "xxxx"
        u, err = _verify_reset_token(tampered)
        assert u is None
        assert err == "invalid"


def test_reset_token_single_use_invalidated_by_hash_change(mock_app):
    with mock_app.app_context():
        user_id = 99
        initial_hash = "hash_v1_initial"
        token = _generate_reset_token(user_id, initial_hash)

        # Hash changes after reset
        new_hash = "hash_v2_updated"
        with patch("app.db.one") as mock_one:
            mock_one.return_value = {
                "id": user_id,
                "email": "bob@example.com",
                "password_hash": new_hash,
                "active": True,
            }
            u, err = _verify_reset_token(token)
            assert u is None
            assert err == "already_used"


def test_reset_token_inactive_user_rejected(mock_app):
    with mock_app.app_context():
        user_id = 7
        user_hash = "active_hash"
        token = _generate_reset_token(user_id, user_hash)

        with patch("app.db.one") as mock_one:
            mock_one.return_value = {
                "id": user_id,
                "email": "disabled@example.com",
                "password_hash": user_hash,
                "active": False,
            }
            u, err = _verify_reset_token(token)
            assert u is None
            assert err == "user_unavailable"


def test_form_csrf_tokens(mock_app):
    with mock_app.app_context():
        tok = _form_token()
        assert _form_token_ok(tok) is True
        assert _form_token_ok("forged_token") is False
        assert _form_token_ok("") is False


def test_unauthenticated_change_password_redirects(mock_app):
    c = mock_app.test_client()
    resp = c.get("/change-password")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_public_routes_accessible_unauthenticated(mock_app):
    c = mock_app.test_client()
    # GET /register
    r_reg = c.get("/register")
    assert r_reg.status_code == 200
    assert "Create Account" in r_reg.get_data(as_text=True)

    # GET /forgot-password
    r_forgot = c.get("/forgot-password")
    assert r_forgot.status_code == 200
    assert "Forgot Password" in r_forgot.get_data(as_text=True)

    # GET /login
    r_login = c.get("/login")
    assert r_login.status_code == 200
    assert "Sign In" in r_login.get_data(as_text=True)
    assert "Forgot password?" in r_login.get_data(as_text=True)


def test_forgot_password_generic_response_for_unknown_user(mock_app):
    c = mock_app.test_client()
    with mock_app.app_context():
        tok = _form_token()
    with patch("app.routes.auth_routes.db.one", return_value=None), \
         patch("app.routes.auth_routes.audit") as mock_audit:
        resp = c.post("/forgot-password", data={
            "login_token": tok,
            "email": "nonexistent@example.com",
        })
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "If that email address is in our system" in html
        mock_audit.assert_called_once()
        assert mock_audit.call_args[0][0] == "password_reset_request"
        assert mock_audit.call_args[0][1] == "denied"


def test_forgot_password_known_user_dispatches_email(mock_app):
    c = mock_app.test_client()
    with mock_app.app_context():
        tok = _form_token()
    user_row = {
        "id": 10,
        "email": "user@example.com",
        "password_hash": "hash123",
        "active": True,
    }
    with patch("app.routes.auth_routes.db.one", return_value=user_row), \
         patch("app.routes.auth_routes.send_email") as mock_send, \
         patch("app.routes.auth_routes.audit") as mock_audit:
        resp = c.post("/forgot-password", data={
            "login_token": tok,
            "email": "user@example.com",
        })
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "If that email address is in our system" in html
        mock_send.assert_called_once()
        assert mock_send.call_args[0][0] == "user@example.com"
        mock_audit.assert_called_once()
        assert mock_audit.call_args[0][0] == "password_reset_request"
        assert mock_audit.call_args[0][1] == "allowed"


def test_reset_password_post_flow(mock_app):
    c = mock_app.test_client()
    with mock_app.app_context():
        tok = _form_token()
        reset_tok = _generate_reset_token(5, "initial_hash")

    user_row = {
        "id": 5,
        "email": "user5@example.com",
        "password_hash": "initial_hash",
        "active": True,
    }

    # 1. Password mismatch
    with patch("app.routes.auth_routes.db.one", return_value=user_row), \
         patch("app.routes.auth_routes.audit") as mock_audit:
        r = c.post(f"/reset-password/{reset_tok}", data={
            "login_token": tok,
            "password": "ValidNewPassword123!",
            "confirm_password": "DifferentPassword123!",
        })
        assert r.status_code == 400
        assert "Passwords do not match" in r.get_data(as_text=True)
        assert mock_audit.call_args[0][1] == "denied"

    # 2. Weak password
    with patch("app.routes.auth_routes.db.one", return_value=user_row), \
         patch("app.routes.auth_routes.audit") as mock_audit:
        r = c.post(f"/reset-password/{reset_tok}", data={
            "login_token": tok,
            "password": "short",
            "confirm_password": "short",
        })
        assert r.status_code == 400
        assert "at least 12 characters" in r.get_data(as_text=True)
        assert mock_audit.call_args[0][1] == "denied"

    # 3. Successful reset updates DB and purges sessions
    with patch("app.routes.auth_routes.db.one", return_value=user_row), \
         patch("app.routes.auth_routes.db.run") as mock_run, \
         patch("app.routes.auth_routes.db.conn") as mock_conn, \
         patch("app.routes.auth_routes.audit") as mock_audit:
        r = c.post(f"/reset-password/{reset_tok}", data={
            "login_token": tok,
            "password": "ValidNewPassword123!",
            "confirm_password": "ValidNewPassword123!",
        })
        assert r.status_code == 200
        assert "Your password has been successfully reset" in r.get_data(as_text=True)
        assert mock_run.call_count == 2
        # Check sessions purge was executed
        assert "DELETE FROM sessions WHERE user_id = %s" in mock_run.call_args_list[1][0][0]
        assert mock_audit.call_args[0][0] == "password_reset"
        assert mock_audit.call_args[0][1] == "allowed"


def test_register_flow_validation_and_id_assignment(mock_app):
    c = mock_app.test_client()
    with mock_app.app_context():
        tok = _form_token()

    # 1. Weak password rejected
    with patch("app.routes.auth_routes.audit") as mock_audit:
        r = c.post("/register", data={
            "login_token": tok,
            "email": "newuser@example.com",
            "password": "weak",
            "role": "owner",
        })
        assert r.status_code == 400
        assert "at least 12 characters" in r.get_data(as_text=True)
        assert mock_audit.call_args[0][1] == "denied"

    # 2. Existing email returns generic error without leaking
    with patch("app.routes.auth_routes.db.one", return_value={"id": 1}), \
         patch("app.routes.auth_routes.audit") as mock_audit:
        r = c.post("/register", data={
            "login_token": tok,
            "email": "existing@example.com",
            "password": "StrongPassword123!",
            "role": "owner",
        })
        assert r.status_code == 400
        assert "Unable to create account" in r.get_data(as_text=True)
        assert mock_audit.call_args[0][1] == "denied"

    # 3. Successful registration assigns SERIAL id and defaults role
    with patch("app.routes.auth_routes.db.one") as mock_one, \
         patch("app.routes.auth_routes.db.conn") as mock_conn, \
         patch("app.routes.auth_routes.audit") as mock_audit:
        # First call checks existing, second call inserts
        mock_one.side_effect = [None, {"id": 123, "email": "brandnew@example.com", "role": "owner"}]
        r = c.post("/register", data={
            "login_token": tok,
            "email": "brandnew@example.com",
            "password": "StrongPassword123!",
            "role": "admin",  # Escalation attempt should be forced to 'owner'
        })
        assert r.status_code == 200
        assert "Account created successfully" in r.get_data(as_text=True)
        # Verify SQL used SERIAL id RETURNING id, role forced to 'owner'
        insert_sql = mock_one.call_args_list[1][0][0]
        insert_args = mock_one.call_args_list[1][0][1]
        assert "INSERT INTO users (email, password_hash, role, active)" in insert_sql
        assert "RETURNING id" in insert_sql
        assert insert_args[2] == "owner"  # Not 'admin'!
        assert mock_audit.call_args[0][0] == "user_register"
        assert mock_audit.call_args[0][1] == "allowed"


def test_rate_limiter_blocks_excessive_requests(mock_app):
    from app.rate_limit import is_rate_limited, clear_rate_limits
    clear_rate_limits()
    key = "login:192.168.1.50"
    limit = 3
    window = 60

    # Enable rate limiting in the test app context, and use DB-less in-memory path
    with mock_app.app_context():
        mock_app.config["ENABLE_RATE_LIMIT_TESTS"] = True
        try:
            limited, _ = is_rate_limited(key, limit, window)
            assert limited is False
            limited, _ = is_rate_limited(key, limit, window)
            assert limited is False
            limited, _ = is_rate_limited(key, limit, window)
            assert limited is False
            # 4th request exceeds limit of 3
            limited, _ = is_rate_limited(key, limit, window)
            assert limited is True
        finally:
            mock_app.config["ENABLE_RATE_LIMIT_TESTS"] = False
            clear_rate_limits()

