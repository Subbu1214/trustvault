from werkzeug.security import generate_password_hash

from . import db

ROLES = ("admin", "owner", "viewer")


def validate_password_strength(password):
    """Enforces minimum 12 characters, and a mix of letters and numbers/symbols."""
    if not password:
        return False, "Password is required."
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    has_alpha = any(c.isalpha() for c in password)
    has_other = any(not c.isalpha() for c in password)
    if not (has_alpha and has_other):
        return False, "Password must include both letters and numbers or symbols."
    return True, None


def create_user(email, password, role):
    email = email.strip().lower()
    if role not in ROLES:
        raise ValueError("bad role")
    ok, err = validate_password_strength(password)
    if not ok:
        raise ValueError(err)
    return db.one(
        "INSERT INTO users(email,password_hash,role) VALUES (%s,%s,%s) RETURNING id,email,role",
        (email, generate_password_hash(password), role),
    )
