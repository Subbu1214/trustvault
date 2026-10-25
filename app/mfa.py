"""Multi-Factor Authentication (TOTP) module.

Provides:
- Encryption & decryption of TOTP secrets at rest via Fernet using a dedicated MFA_ENCRYPTION_KEY.
- TOTP verification with time-step replay rejection (tracking last_totp_timestep).
- 10 cryptographically random, single-use, HMAC-SHA256 hashed recovery codes.
- Constant-time verification of codes.
- Inline base64 QR code generation for enrollment.
"""
import base64
import datetime
import hashlib
import hmac
import io
import json
import secrets
from cryptography.fernet import Fernet
from flask import current_app
import pyotp
import qrcode


def _get_mfa_key():
    raw_key = current_app.config.get("MFA_ENCRYPTION_KEY")
    if not raw_key:
        if current_app.config.get("TESTING") or current_app.config.get("ENV") == "development":
            # Deterministic test key
            return base64.urlsafe_b64encode(hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest())
        raise RuntimeError(
            "MFA_ENCRYPTION_KEY must be configured in production. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    if isinstance(raw_key, str):
        raw_key = raw_key.strip().encode()
    try:
        decoded = base64.urlsafe_b64decode(raw_key)
        if len(decoded) == 32:
            return raw_key
    except Exception:
        pass
    return base64.urlsafe_b64encode(hashlib.sha256(raw_key).digest())


def _get_fernet():
    return Fernet(_get_mfa_key())


def encrypt_totp_secret(secret_str):
    if not secret_str:
        return None
    return _get_fernet().encrypt(secret_str.encode()).decode()


def decrypt_totp_secret(encrypted_str):
    if not encrypted_str:
        return None
    try:
        return _get_fernet().decrypt(encrypted_str.encode()).decode()
    except Exception:
        return None


def hash_recovery_code(code_str):
    """Computes HMAC-SHA256 of the recovery code using the server MFA key."""
    clean = (code_str or "").strip().upper()
    key = _get_mfa_key()
    return hmac.new(key, clean.encode(), hashlib.sha256).hexdigest()


def generate_recovery_codes(count=10):
    """Generates plain recovery codes and their stored HMAC-SHA256 hashed records."""
    plain_codes = []
    hashed_records = []
    for _ in range(count):
        code = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
        code_hash = hash_recovery_code(code)
        plain_codes.append(code)
        hashed_records.append({"hash": code_hash, "used": False})
    return plain_codes, hashed_records


def verify_recovery_code(submitted_code, hashed_records):
    """
    Checks submitted_code against unused recovery codes in constant time.
    Returns (match_found, updated_records).
    """
    if not submitted_code or not hashed_records:
        return False, hashed_records
    submitted_hash = hash_recovery_code(submitted_code)

    if isinstance(hashed_records, str):
        try:
            records = json.loads(hashed_records)
        except Exception:
            records = []
    else:
        records = list(hashed_records)

    matched = False
    new_records = []
    for rec in records:
        if not rec.get("used") and hmac.compare_digest(rec.get("hash", ""), submitted_hash) and not matched:
            matched = True
            new_records.append({"hash": rec["hash"], "used": True})
        else:
            new_records.append(rec)
    return matched, new_records


def verify_mfa_code(user_row, code, for_time=None):
    """
    Verifies either a 6-digit TOTP code (with replay check) or a single-use recovery code.
    Returns (success, is_recovery_code, updated_recovery_records, new_timestep).
    """
    if not user_row or not user_row.get("mfa_enabled"):
        return True, False, user_row.get("mfa_recovery_codes") if user_row else None, None

    clean_code = (code or "").strip().replace(" ", "").replace("-", "")
    secret = decrypt_totp_secret(user_row.get("mfa_secret_encrypted"))
    last_timestep = user_row.get("last_totp_timestep") or 0

    # 1. Try TOTP code
    if secret and clean_code.isdigit() and len(clean_code) == 6:
        totp = pyotp.TOTP(secret)
        now_dt = for_time or datetime.datetime.now()
        base_tc = totp.timecode(now_dt)

        matched_step = None
        for offset in (-1, 0, 1):
            cand_tc = base_tc + offset
            if pyotp.utils.strings_equal(clean_code, totp.at(now_dt, offset)):
                matched_step = cand_tc
                break

        if matched_step is not None:
            # Replay protection: timestep must be strictly greater than last accepted
            if matched_step <= last_timestep:
                return False, False, user_row.get("mfa_recovery_codes"), None
            return True, False, user_row.get("mfa_recovery_codes"), matched_step

    # 2. Try recovery code
    matched, updated = verify_recovery_code(code, user_row.get("mfa_recovery_codes"))
    if matched:
        return True, True, updated, None

    return False, False, user_row.get("mfa_recovery_codes"), None


def generate_qr_data_uri(provisioning_uri):
    """Generates a data:image/png;base64,... URI for the QR code."""
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"
