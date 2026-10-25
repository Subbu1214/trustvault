import hashlib
import hmac
import json
import secrets
from flask import (
    Blueprint, current_app, g, make_response, redirect,
    render_template, request, url_for
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
import pyotp
from werkzeug.security import check_password_hash, generate_password_hash

from .. import auth, db
from ..audit import audit
from ..email import send_email
from ..mfa import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_qr_data_uri,
    generate_recovery_codes,
    verify_mfa_code,
)
from ..rate_limit import rate_limit
from ..users import validate_password_strength

bp = Blueprint("auth", __name__)
DUMMY_HASH = generate_password_hash("not-a-real-password")   # equalise timing for unknown emails


def _form_token():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="auth-form-csrf").dumps("x")


def _form_token_ok(tok):
    if not tok:
        return False
    try:
        URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="auth-form-csrf").loads(tok, max_age=900)
        return True
    except BadSignature:
        pass
    try:
        URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="login-csrf").loads(tok, max_age=900)
        return True
    except BadSignature:
        return False


def _mfa_challenge_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="mfa-login-challenge")


def _create_mfa_challenge_token(user_id):
    ip = request.remote_addr or "127.0.0.1"
    ua = hashlib.sha256(request.headers.get("User-Agent", "").encode()).hexdigest()[:16]
    nonce = secrets.token_hex(8)
    return _mfa_challenge_serializer().dumps({"uid": user_id, "ip": ip, "ua": ua, "nonce": nonce})


def _verify_mfa_challenge_token(token):
    try:
        data = _mfa_challenge_serializer().loads(token, max_age=300)
    except (BadSignature, SignatureExpired):
        return None, "invalid_or_expired"
    cur_ip = request.remote_addr or "127.0.0.1"
    cur_ua = hashlib.sha256(request.headers.get("User-Agent", "").encode()).hexdigest()[:16]
    if not (hmac.compare_digest(data.get("ip", ""), cur_ip) and hmac.compare_digest(data.get("ua", ""), cur_ua)):
        return None, "client_mismatch"
    return data.get("uid"), None


def _mfa_enrollment_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="mfa-enrollment")


def _generate_reset_token(user_id, password_hash):
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="password-reset")
    sig = hashlib.sha256(password_hash.encode()).hexdigest()[:16]
    return s.dumps({"uid": user_id, "sig": sig})


def _verify_reset_token(token):
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="password-reset")
    try:
        data = s.loads(token, max_age=900)  # 15-minute expiry
    except SignatureExpired:
        return None, "expired"
    except BadSignature:
        return None, "invalid"

    uid = data.get("uid")
    sig = data.get("sig")
    if not uid or not sig:
        return None, "invalid"

    u = db.one("SELECT * FROM users WHERE id = %s", (uid,))
    if not u or not u["active"]:
        return None, "user_unavailable"

    expected_sig = hashlib.sha256(u["password_hash"].encode()).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected_sig):
        return None, "already_used"

    return u, None


@bp.get("/login")
def login_form():
    if g.user:
        return redirect(url_for("docs.list_docs"))
    return render_template("login.html", token=_form_token(), error=None)


@bp.post("/login")
@rate_limit(limit=5, window_seconds=60, action_name="login")
def login_submit():
    cfg = current_app.config
    token_candidate = request.form.get("login_token") or request.form.get("token") or request.form.get("csrf_token", "")
    if not _form_token_ok(token_candidate):
        return render_template("login.html", token=_form_token(), error="Reload the page and try again."), 400
    email = request.form.get("email", "").strip().lower()[:254]
    password = request.form.get("password", "")[:200]
    u = db.one("SELECT * FROM users WHERE email = %s", (email,))
    locked = bool(u and db.one("SELECT 1 AS x FROM users WHERE id=%s AND locked_until > now()", (u["id"],)))
    good = check_password_hash(u["password_hash"] if u else DUMMY_HASH, password)
    if not (u and good and u["active"] and not locked):
        if u:
            db.run("""UPDATE users SET failed_logins = failed_logins + 1,
                         locked_until = CASE WHEN failed_logins + 1 >= %s
                                        THEN now() + make_interval(mins => %s) ELSE locked_until END
                       WHERE id = %s""", (cfg["MAX_FAILED_LOGINS"], cfg["LOCKOUT_MINUTES"], u["id"]))
            db.conn().commit()
        audit("login", "denied", actor=None, email=email,
              reason="locked" if locked else ("disabled" if u and not u["active"] else "bad_credentials"))
        return render_template("login.html", token=_form_token(),
                               error="Email or password is wrong, or the account is locked."), 401

    # Check if MFA is enabled on this account
    if u.get("mfa_enabled"):
        challenge_token = _create_mfa_challenge_token(u["id"])
        return render_template(
            "login.html",
            mfa_challenge_mode=True,
            mfa_token=challenge_token,
            token=_form_token(),
            error=None
        )

    db.run("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = %s", (u["id"],))
    old = request.cookies.get(auth.COOKIE)
    if old:                                                  # new session id on every login
        db.run("DELETE FROM sessions WHERE id = %s", (auth.token_hash(old),))
    tok = auth.create_session(u["id"])
    audit("login", "allowed", actor={"id": u["id"], "email": u["email"]})
    resp = redirect(url_for("docs.list_docs"))
    resp.set_cookie(auth.COOKIE, tok, httponly=True, secure=cfg["COOKIE_SECURE"], samesite="Lax",
                    max_age=cfg["SESSION_MAX_HOURS"] * 3600)
    return resp


@bp.get("/login/mfa", endpoint="login_mfa")
def login_mfa_form():
    if g.user:
        return redirect(url_for("docs.list_docs"))
    token = request.args.get("mfa_token", "")
    return render_template("login.html", mfa_challenge_mode=True, mfa_token=token, token=_form_token(), error=None)


@bp.post("/login/mfa")
@rate_limit(limit=5, window_seconds=60, action_name="login_mfa")
def login_mfa_submit():
    cfg = current_app.config
    token_candidate = request.form.get("login_token") or request.form.get("token") or request.form.get("csrf_token", "")
    if not _form_token_ok(token_candidate):
        return render_template("login.html", token=_form_token(), error="Session expired. Please try again."), 400

    mfa_token = request.form.get("mfa_token", "")
    uid, err = _verify_mfa_challenge_token(mfa_token)
    if err:
        return render_template("login.html", token=_form_token(), error="MFA session invalid or expired. Please sign in again."), 400

    u = db.one("SELECT * FROM users WHERE id = %s", (uid,))
    if not u or not u["active"]:
        return render_template("login.html", token=_form_token(), error="Account unavailable."), 401

    locked = bool(db.one("SELECT 1 AS x FROM users WHERE id=%s AND locked_until > now()", (u["id"],)))
    if locked:
        audit("mfa_failed", "denied", actor=None, email=u["email"], target_user_id=u["id"], reason="account_locked")
        return render_template("login.html", token=_form_token(), error="Account is locked due to repeated failures."), 401

    code = request.form.get("code", "")
    success, is_recovery, updated_codes, new_timestep = verify_mfa_code(u, code)

    if not success:
        db.run("""UPDATE users SET failed_logins = failed_logins + 1,
                     locked_until = CASE WHEN failed_logins + 1 >= %s
                                    THEN now() + make_interval(mins => %s) ELSE locked_until END
                   WHERE id = %s""", (cfg["MAX_FAILED_LOGINS"], cfg["LOCKOUT_MINUTES"], u["id"]))
        db.conn().commit()
        audit("mfa_failed", "denied", actor=None, email=u["email"], target_user_id=u["id"], reason="bad_mfa_code")
        return render_template(
            "login.html",
            mfa_challenge_mode=True,
            mfa_token=mfa_token,
            token=_form_token(),
            error="Invalid authenticator code or recovery code."
        ), 401

    # Code is valid
    if is_recovery:
        db.run("UPDATE users SET mfa_recovery_codes = %s WHERE id = %s", (json.dumps(updated_codes), u["id"]))
        audit("recovery_code_used", "allowed", actor={"id": u["id"], "email": u["email"]}, target_user_id=u["id"])
    elif new_timestep is not None:
        db.run("UPDATE users SET last_totp_timestep = %s WHERE id = %s", (new_timestep, u["id"]))

    db.run("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = %s", (u["id"],))
    old = request.cookies.get(auth.COOKIE)
    if old:
        db.run("DELETE FROM sessions WHERE id = %s", (auth.token_hash(old),))
    tok = auth.create_session(u["id"])
    audit("login", "allowed", actor={"id": u["id"], "email": u["email"]}, mfa_used="recovery_code" if is_recovery else "totp")

    resp = redirect(url_for("docs.list_docs"))
    resp.set_cookie(auth.COOKIE, tok, httponly=True, secure=cfg["COOKIE_SECURE"], samesite="Lax",
                    max_age=cfg["SESSION_MAX_HOURS"] * 3600)
    return resp


@bp.post("/logout")
def logout():
    db.run("DELETE FROM sessions WHERE id = %s", (g.session["id"],))
    audit("logout", "allowed", actor=g.user)
    resp = make_response(redirect(url_for("auth.login_form")))
    resp.delete_cookie(auth.COOKIE)
    return resp


@bp.get("/register", endpoint="register")
def register_form():
    if g.user:
        return redirect(url_for("docs.list_docs"))
    return render_template("login.html", register_mode=True, token=_form_token(), error=None, success=None)


@bp.post("/register")
def register_submit():
    token_candidate = request.form.get("login_token") or request.form.get("token") or request.form.get("csrf_token", "")
    if not _form_token_ok(token_candidate):
        return render_template("login.html", register_mode=True, token=_form_token(), error="Session expired. Please try again."), 400

    email = request.form.get("email", "").strip().lower()[:254]
    password = request.form.get("password", "")
    role = request.form.get("role", "owner").strip()

    if role not in ("owner", "viewer"):
        role = "owner"

    if not email or "@" not in email or len(email) < 5:
        audit("user_register", "denied", email=email, reason="invalid_email")
        return render_template("login.html", register_mode=True, token=_form_token(), error="Please provide a valid email address."), 400

    ok, err_msg = validate_password_strength(password)
    if not ok:
        audit("user_register", "denied", email=email, reason="weak_password")
        return render_template("login.html", register_mode=True, token=_form_token(), error=err_msg), 400

    existing = db.one("SELECT id FROM users WHERE email = %s", (email,))
    if existing:
        check_password_hash(DUMMY_HASH, password)
        audit("user_register", "denied", email=email, reason="email_exists")
        return render_template(
            "login.html",
            register_mode=True,
            token=_form_token(),
            error="Unable to create account. If you already have an account, please sign in."
        ), 400

    pw_hash = generate_password_hash(password)
    u = db.one(
        "INSERT INTO users (email, password_hash, role, active) VALUES (%s, %s, %s, true) RETURNING id, email, role",
        (email, pw_hash, role)
    )
    db.conn().commit()
    audit("user_register", "allowed", email=email, target_user_id=u["id"], role=role)
    return render_template("login.html", register_mode=False, token=_form_token(),
                           success="Account created successfully! You can now sign in.")


@bp.get("/change-password", endpoint="change_password")
def change_password_form():
    return render_template("change_password.html", error=None, success=None)


@bp.post("/change-password")
def change_password_submit():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not current_password or not new_password:
        return render_template("change_password.html", error="All fields are required."), 400

    if new_password != confirm_password:
        audit("password_change", "denied", actor=g.user, reason="password_mismatch")
        return render_template("change_password.html", error="New passwords do not match."), 400

    u = db.one("SELECT id, password_hash FROM users WHERE id = %s", (g.user["id"],))
    if not u or not check_password_hash(u["password_hash"], current_password):
        audit("password_change", "denied", actor=g.user, reason="wrong_current_password")
        return render_template("change_password.html", error="Current password is incorrect."), 400

    ok, err_msg = validate_password_strength(new_password)
    if not ok:
        audit("password_change", "denied", actor=g.user, reason="weak_password")
        return render_template("change_password.html", error=err_msg), 400

    if check_password_hash(u["password_hash"], new_password):
        audit("password_change", "denied", actor=g.user, reason="password_reuse")
        return render_template("change_password.html", error="New password must be different from your current password."), 400

    new_hash = generate_password_hash(new_password)
    db.run(
        "UPDATE users SET password_hash = %s, failed_logins = 0, locked_until = NULL WHERE id = %s",
        (new_hash, g.user["id"])
    )
    db.run("DELETE FROM sessions WHERE user_id = %s AND id != %s", (g.user["id"], g.session["id"]))
    db.conn().commit()

    audit("password_change", "allowed", actor=g.user, target_user_id=g.user["id"])
    return render_template("change_password.html", success="Your password has been changed. All other active sessions have been invalidated.")


@bp.get("/forgot-password", endpoint="forgot_password")
def forgot_password_form():
    if g.user:
        return redirect(url_for("docs.list_docs"))
    return render_template("login.html", forgot_mode=True, token=_form_token(), error=None, success=None)


@bp.post("/forgot-password")
@rate_limit(limit=5, window_seconds=600, action_name="forgot_password")
def forgot_password_submit():
    token_candidate = request.form.get("login_token") or request.form.get("token") or request.form.get("csrf_token", "")
    if not _form_token_ok(token_candidate):
        return render_template("login.html", forgot_mode=True, token=_form_token(), error="Session expired. Please try again."), 400

    email = request.form.get("email", "").strip().lower()[:254]
    u = db.one("SELECT id, email, password_hash, active FROM users WHERE email = %s", (email,))
    uniform_msg = "If that email address is in our system, you will receive password reset instructions shortly."

    if u and u["active"]:
        token = _generate_reset_token(u["id"], u["password_hash"])
        reset_link = url_for("auth.reset_password", token=token, _external=True)
        body = (
            f"Hello,\n\n"
            f"A password reset was requested for your TrustVault account ({u['email']}).\n"
            f"Use the following link within 15 minutes to reset your password:\n\n"
            f"{reset_link}\n\n"
            f"If you did not request this reset, please contact your administrator immediately.\n"
            f"This link can only be used once.\n"
        )
        send_email(u["email"], "TrustVault Password Reset Request", body)
        audit("password_reset_request", "allowed", email=email, target_user_id=u["id"])
    else:
        check_password_hash(DUMMY_HASH, "timing-defense")
        audit("password_reset_request", "denied", email=email, reason="not_found" if not u else "inactive")

    return render_template("login.html", forgot_mode=True, token=_form_token(), success=uniform_msg)


@bp.get("/reset-password/<token>", endpoint="reset_password")
def reset_password_form(token):
    u, err = _verify_reset_token(token)
    if err:
        audit("password_reset", "denied", reason=err, token_prefix=token[:10])
        return render_template("login.html", reset_mode=True, reset_error="This password reset link is invalid or has expired.", token=_form_token())

    return render_template(
        "login.html",
        reset_mode=True,
        reset_token=token,
        mfa_required=bool(u.get("mfa_enabled")),
        token=_form_token(),
        error=None
    )


@bp.post("/reset-password/<token>")
@rate_limit(limit=5, window_seconds=600, action_name="reset_password")
def reset_password_submit(token):
    token_candidate = request.form.get("login_token") or request.form.get("token") or request.form.get("csrf_token", "")
    if not _form_token_ok(token_candidate):
        return render_template("login.html", reset_mode=True, reset_token=token, token=_form_token(), error="Session expired. Please try again."), 400

    u, err = _verify_reset_token(token)
    if err:
        audit("password_reset", "denied", reason=err, token_prefix=token[:10])
        return render_template("login.html", reset_mode=True, reset_error="This password reset link is invalid or has expired.", token=_form_token()), 400

    # If user has MFA enabled, require valid TOTP or recovery code before resetting!
    is_recovery, updated_codes, new_timestep = False, None, None
    if u.get("mfa_enabled"):
        mfa_code = request.form.get("mfa_code", "")
        success, is_recovery, updated_codes, new_timestep = verify_mfa_code(u, mfa_code)
        if not success:
            audit("password_reset", "denied", target_user_id=u["id"], email=u["email"], reason="mfa_verification_failed")
            return render_template(
                "login.html",
                reset_mode=True,
                reset_token=token,
                mfa_required=True,
                token=_form_token(),
                error="Invalid authenticator code or recovery code. Password reset blocked."
            ), 400

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if password != confirm_password:
        audit("password_reset", "denied", target_user_id=u["id"], email=u["email"], reason="password_mismatch")
        return render_template(
            "login.html",
            reset_mode=True,
            reset_token=token,
            mfa_required=bool(u.get("mfa_enabled")),
            token=_form_token(),
            error="Passwords do not match."
        ), 400

    ok, err_msg = validate_password_strength(password)
    if not ok:
        audit("password_reset", "denied", target_user_id=u["id"], email=u["email"], reason="weak_password")
        return render_template(
            "login.html",
            reset_mode=True,
            reset_token=token,
            mfa_required=bool(u.get("mfa_enabled")),
            token=_form_token(),
            error=err_msg
        ), 400

    new_hash = generate_password_hash(password)
    if is_recovery and updated_codes:
        db.run(
            "UPDATE users SET password_hash = %s, failed_logins = 0, locked_until = NULL, mfa_recovery_codes = %s WHERE id = %s",
            (new_hash, json.dumps(updated_codes), u["id"])
        )
        audit("recovery_code_used", "allowed", email=u["email"], target_user_id=u["id"], context="password_reset")
    elif new_timestep is not None:
        db.run(
            "UPDATE users SET password_hash = %s, failed_logins = 0, locked_until = NULL, last_totp_timestep = %s WHERE id = %s",
            (new_hash, new_timestep, u["id"])
        )
    else:
        db.run(
            "UPDATE users SET password_hash = %s, failed_logins = 0, locked_until = NULL WHERE id = %s",
            (new_hash, u["id"])
        )

    # Invalidate all active sessions for this user
    db.run("DELETE FROM sessions WHERE user_id = %s", (u["id"],))
    db.conn().commit()

    audit("password_reset", "allowed", target_user_id=u["id"], email=u["email"])
    return render_template(
        "login.html",
        register_mode=False,
        token=_form_token(),
        success="Your password has been successfully reset. Please sign in with your new password."
    )


@bp.get("/mfa/setup", endpoint="mfa_setup")
def mfa_setup_form():
    u = db.one("SELECT id, email, mfa_enabled FROM users WHERE id = %s", (g.user["id"],))
    if u and u.get("mfa_enabled"):
        return render_template("mfa_setup.html", already_enabled=True, error=None, success=None)

    secret = pyotp.random_base32()
    plain_codes, hashed_records = generate_recovery_codes(10)
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=g.user["email"], issuer_name="TrustVault")
    qr_data_uri = generate_qr_data_uri(totp_uri)
    enrollment_token = _mfa_enrollment_serializer().dumps({
        "uid": g.user["id"],
        "secret": secret,
        "hashed_codes": hashed_records,
        "plain_codes": plain_codes,
    })

    return render_template(
        "mfa_setup.html",
        qr_data_uri=qr_data_uri,
        secret=secret,
        plain_codes=plain_codes,
        enrollment_token=enrollment_token,
        already_enabled=False,
        error=None,
        success=None
    )


@bp.post("/mfa/setup")
@rate_limit(limit=5, window_seconds=300, action_name="mfa_setup")
def mfa_setup_submit():
    current_password = request.form.get("current_password", "")
    code = request.form.get("code", "")
    enrollment_token = request.form.get("enrollment_token", "")

    try:
        data = _mfa_enrollment_serializer().loads(enrollment_token, max_age=600)
    except (BadSignature, SignatureExpired):
        audit("mfa_enabled", "denied", actor=g.user, reason="enrollment_token_expired")
        return render_template("mfa_setup.html", error="Enrollment session expired. Please reload and try again."), 400

    u = db.one("SELECT id, password_hash, mfa_enabled FROM users WHERE id = %s", (g.user["id"],))
    if not u or not check_password_hash(u["password_hash"], current_password):
        audit("mfa_enabled", "denied", actor=g.user, reason="wrong_current_password")
        return render_template("mfa_setup.html", error="Current password is incorrect.", enrollment_token=enrollment_token), 400

    totp = pyotp.TOTP(data["secret"])
    if not totp.verify(code.strip().replace(" ", ""), valid_window=1):
        audit("mfa_enabled", "denied", actor=g.user, reason="invalid_code")
        return render_template("mfa_setup.html", error="Invalid verification code. Please check your authenticator app.", enrollment_token=enrollment_token), 400

    enc_secret = encrypt_totp_secret(data["secret"])
    db.run(
        "UPDATE users SET mfa_enabled = true, mfa_secret_encrypted = %s, mfa_recovery_codes = %s WHERE id = %s",
        (enc_secret, json.dumps(data["hashed_codes"]), g.user["id"])
    )
    db.conn().commit()

    audit("mfa_enabled", "allowed", actor=g.user, target_user_id=g.user["id"])
    return render_template(
        "mfa_setup.html",
        already_enabled=True,
        enrolled_just_now=True,
        plain_codes=data["plain_codes"],
        success="Two-Factor Authentication is now enabled on your account."
    )


@bp.post("/mfa/disable")
@rate_limit(limit=5, window_seconds=300, action_name="mfa_disable")
def mfa_disable_submit():
    current_password = request.form.get("current_password", "")
    code = request.form.get("code", "")
    u = db.one("SELECT * FROM users WHERE id = %s", (g.user["id"],))
    if not u or not check_password_hash(u["password_hash"], current_password):
        audit("mfa_disabled", "denied", actor=g.user, reason="wrong_current_password")
        return render_template("mfa_setup.html", already_enabled=True, error="Current password is incorrect. MFA was not disabled."), 400

    success, is_rec, _, _ = verify_mfa_code(u, code)
    if not success:
        audit("mfa_disabled", "denied", actor=g.user, reason="invalid_mfa_code")
        return render_template("mfa_setup.html", already_enabled=True, error="Invalid authentication code or recovery code. MFA was not disabled."), 400

    db.run(
        "UPDATE users SET mfa_enabled = false, mfa_secret_encrypted = NULL, mfa_recovery_codes = '[]'::jsonb, last_totp_timestep = 0 WHERE id = %s",
        (g.user["id"],)
    )
    db.conn().commit()

    audit("mfa_disabled", "allowed", actor=g.user, target_user_id=g.user["id"])
    return redirect(url_for("auth.mfa_setup"))
