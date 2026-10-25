import datetime
import hashlib
import json
import secrets
from unittest.mock import MagicMock, patch
import pyotp
import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from app.mfa import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_qr_data_uri,
    generate_recovery_codes,
    verify_mfa_code,
    verify_recovery_code,
    _get_mfa_key,
)
from app.routes.auth_routes import (
    _form_token,
    _create_mfa_challenge_token,
    _verify_mfa_challenge_token,
    _generate_reset_token,
    mfa_disable_submit,
)


@pytest.fixture
def mock_app():
    return create_app({
        "SECRET_KEY": "m" * 32,
        "MFA_ENCRYPTION_KEY": "k" * 32,
        "DATABASE_URL": "postgresql://test:test@localhost:5432/test",
        "STORAGE_BACKEND": "local",
        "LOCAL_STORAGE_DIR": "tmp_store",
        "TESTING": True,
        "COOKIE_SECURE": False,
    })


def test_totp_secret_encryption_at_rest(mock_app):
    with mock_app.app_context():
        raw_secret = pyotp.random_base32()
        encrypted = encrypt_totp_secret(raw_secret)
        assert encrypted != raw_secret
        assert isinstance(encrypted, str)

        decrypted = decrypt_totp_secret(encrypted)
        assert decrypted == raw_secret
        assert decrypt_totp_secret("corrupted_ciphertext") is None


def test_mfa_encryption_key_required_in_production(mock_app):
    with mock_app.app_context():
        # In production mode without key, raises RuntimeError
        with patch.dict(mock_app.config, {"MFA_ENCRYPTION_KEY": "", "ENV": "production", "TESTING": False}):
            with pytest.raises(RuntimeError) as exc_info:
                _get_mfa_key()
            assert "MFA_ENCRYPTION_KEY must be configured in production" in str(exc_info.value)


def test_recovery_codes_hmac_hashing_and_single_use(mock_app):
    with mock_app.app_context():
        plain, hashed = generate_recovery_codes(10)
        assert len(plain) == 10
        assert len(hashed) == 10

        for p in plain:
            assert len(p) == 9
            assert p[4] == "-"

        # Single-use check
        first_code = plain[0]
        matched, updated = verify_recovery_code(first_code, hashed)
        assert matched is True
        assert updated[0]["used"] is True

        # Replay must fail
        matched_replay, _ = verify_recovery_code(first_code, updated)
        assert matched_replay is False


def test_totp_replay_prevention(mock_app):
    with mock_app.app_context():
        secret = pyotp.random_base32()
        enc_secret = encrypt_totp_secret(secret)
        totp = pyotp.TOTP(secret)
        code = totp.now()

        user_row = {
            "id": 1,
            "email": "user@example.com",
            "mfa_enabled": True,
            "mfa_secret_encrypted": enc_secret,
            "mfa_recovery_codes": [],
            "last_totp_timestep": 0,
        }

        # First verification succeeds and returns new_timestep
        ok, is_rec, _, new_step = verify_mfa_code(user_row, code)
        assert ok is True
        assert is_rec is False
        assert new_step is not None
        assert new_step > 0

        # Updating user row with accepted timestep
        user_row["last_totp_timestep"] = new_step

        # Second verification with exact same code/timestep must be REJECTED as replay
        ok_replay, _, _, _ = verify_mfa_code(user_row, code)
        assert ok_replay is False


def test_mfa_challenge_token_client_binding(mock_app):
    c = mock_app.test_client()
    with mock_app.test_request_context(environ_base={"REMOTE_ADDR": "198.51.100.10", "HTTP_USER_AGENT": "VaultClient/1.0"}):
        tok = _create_mfa_challenge_token(user_id=12)

        # Same client verifies
        uid, err = _verify_mfa_challenge_token(tok)
        assert err is None
        assert uid == 12

    # Different IP or User-Agent fails binding
    with mock_app.test_request_context(environ_base={"REMOTE_ADDR": "203.0.113.5", "HTTP_USER_AGENT": "AttackerBrowser/2.0"}):
        uid, err = _verify_mfa_challenge_token(tok)
        assert uid is None
        assert err == "client_mismatch"


def test_mfa_two_step_login_flow(mock_app):
    c = mock_app.test_client()
    with mock_app.app_context():
        tok = _form_token()
        secret = pyotp.random_base32()
        enc_secret = encrypt_totp_secret(secret)

    user_row = {
        "id": 20,
        "email": "mfa_user@example.com",
        "password_hash": generate_password_hash("Password12345!"),
        "role": "owner",
        "active": True,
        "mfa_enabled": True,
        "mfa_secret_encrypted": enc_secret,
        "mfa_recovery_codes": [],
        "last_totp_timestep": 0,
        "locked_until": None,
    }

    # Step 1: POST /login with correct credentials renders MFA challenge, NO session cookie yet
    with patch("app.routes.auth_routes.db.one") as mock_one:
        mock_one.side_effect = [user_row, None]
        r1 = c.post("/login", data={
            "login_token": tok,
            "email": "mfa_user@example.com",
            "password": "Password12345!",
        })
        assert r1.status_code == 200
        assert "Two-Step Verification" in r1.get_data(as_text=True)
        assert "tv_session" not in r1.headers.get("Set-Cookie", "")

    # Extract mfa_token
    import re
    mfa_tok_match = re.search(r'name="mfa_token" value="([^"]+)"', r1.get_data(as_text=True))
    assert mfa_tok_match is not None
    challenge_token = mfa_tok_match.group(1)

    # Step 2: POST /login/mfa with wrong code increments failed_logins and audits refusal
    with patch("app.routes.auth_routes.db.one") as mock_one, \
         patch("app.routes.auth_routes.db.run") as mock_run, \
         patch("app.routes.auth_routes.db.conn") as mock_conn, \
         patch("app.routes.auth_routes.audit") as mock_audit:
        mock_one.side_effect = [user_row, None]
        r2_bad = c.post("/login/mfa", data={
            "login_token": tok,
            "mfa_token": challenge_token,
            "code": "999999",
        })
        assert r2_bad.status_code == 401
        assert "Invalid authenticator code" in r2_bad.get_data(as_text=True)
        assert mock_audit.call_args[0][0] == "mfa_failed"
        assert mock_audit.call_args[0][1] == "denied"

    # Step 3: POST /login/mfa with correct code establishes session cookie
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    with patch("app.routes.auth_routes.db.one") as mock_one, \
         patch("app.routes.auth_routes.db.run") as mock_run, \
         patch("app.routes.auth_routes.auth.create_session", return_value="sess_123"), \
         patch("app.routes.auth_routes.audit") as mock_audit:
        mock_one.side_effect = [user_row, None]
        r2_good = c.post("/login/mfa", data={
            "login_token": tok,
            "mfa_token": challenge_token,
            "code": valid_code,
        })
        assert r2_good.status_code == 302
        assert "/documents" in r2_good.headers["Location"]
        assert "tv_session" in r2_good.headers["Set-Cookie"]
        assert mock_audit.call_args[0][0] == "login"
        assert mock_audit.call_args[0][1] == "allowed"


def test_mfa_disable_requires_password_and_code(mock_app):
    pw_hash = generate_password_hash("CorrectPassword123!")
    secret = pyotp.random_base32()
    with mock_app.app_context():
        enc_secret = encrypt_totp_secret(secret)
    user_row = {
        "id": 40,
        "email": "user40@example.com",
        "password_hash": pw_hash,
        "mfa_enabled": True,
        "mfa_secret_encrypted": enc_secret,
        "mfa_recovery_codes": [],
        "last_totp_timestep": 0,
    }

    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    # 1. Wrong password rejected even with valid code
    with mock_app.test_request_context(method="POST", data={"current_password": "WrongPassword!", "code": valid_code}):
        from flask import g
        g.user = {"id": 40, "email": "user40@example.com", "role": "owner"}
        g.session = {"id": "sid", "csrf": "csrftok"}

        with patch("app.routes.auth_routes.db.one", return_value=user_row), \
             patch("app.routes.auth_routes.audit") as mock_audit:
            resp, code = mfa_disable_submit()
            assert code == 400
            assert mock_audit.call_args[0][0] == "mfa_disabled"
            assert mock_audit.call_args[0][1] == "denied"
            assert mock_audit.call_args[1]["reason"] == "wrong_current_password"

    # 2. Correct password but wrong code rejected
    with mock_app.test_request_context(method="POST", data={"current_password": "CorrectPassword123!", "code": "000000"}):
        from flask import g
        g.user = {"id": 40, "email": "user40@example.com", "role": "owner"}
        g.session = {"id": "sid", "csrf": "csrftok"}

        with patch("app.routes.auth_routes.db.one", return_value=user_row), \
             patch("app.routes.auth_routes.audit") as mock_audit:
            resp, code = mfa_disable_submit()
            assert code == 400
            assert mock_audit.call_args[0][0] == "mfa_disabled"
            assert mock_audit.call_args[0][1] == "denied"
            assert mock_audit.call_args[1]["reason"] == "invalid_mfa_code"

    # 3. Correct password AND correct code accepted
    with mock_app.test_request_context(method="POST", data={"current_password": "CorrectPassword123!", "code": valid_code}):
        from flask import g
        g.user = {"id": 40, "email": "user40@example.com", "role": "owner"}
        g.session = {"id": "sid", "csrf": "csrftok"}

        with patch("app.routes.auth_routes.db.one", return_value=user_row), \
             patch("app.routes.auth_routes.db.run") as mock_run, \
             patch("app.routes.auth_routes.db.conn") as mock_conn, \
             patch("app.routes.auth_routes.audit") as mock_audit:
            resp = mfa_disable_submit()
            assert resp.status_code == 302
            assert mock_audit.call_args[0][0] == "mfa_disabled"
            assert mock_audit.call_args[0][1] == "allowed"
