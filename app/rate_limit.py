"""Rate limiter supporting PostgreSQL shared storage and in-memory fallback.

Features:
- Multi-worker safe: uses PostgreSQL table `rate_limits` when available.
- Defense-in-depth against log flooding: only audits on the FIRST breach per window.
- In-memory fallback for local unit tests.
- Trusted client IP resolution via Werkzeug ProxyFix.
"""
import time
from collections import defaultdict
from functools import wraps
from threading import Lock
from flask import current_app, has_request_context, render_template, request

from .audit import audit

_mem_store = defaultdict(list)
_mem_lock = Lock()


def _is_rate_limited_memory(key, limit, window_seconds):
    now = time.time()
    cutoff = now - window_seconds
    with _mem_lock:
        timestamps = _mem_store[key]
        valid = [ts for ts in timestamps if ts > cutoff]
        count = len(valid)
        is_limited = count >= limit
        is_first_breach = count == limit
        valid.append(now)
        _mem_store[key] = valid
        return is_limited, is_first_breach


def _is_rate_limited_db(key, limit, window_seconds):
    from . import db
    try:
        # Atomic upsert in rate_limits table
        sql = """
            INSERT INTO rate_limits (key, count, reset_at)
            VALUES (%s, 1, now() + make_interval(secs => %s))
            ON CONFLICT (key) DO UPDATE
            SET count = CASE WHEN rate_limits.reset_at < now() THEN 1 ELSE rate_limits.count + 1 END,
                reset_at = CASE WHEN rate_limits.reset_at < now() THEN now() + make_interval(secs => %s) ELSE rate_limits.reset_at END
            RETURNING count, reset_at
        """
        row = db.one(sql, (key, window_seconds, window_seconds))
        if row:
            db.conn().commit()
            count = row["count"]
            is_limited = count > limit
            is_first_breach = count == limit + 1
            return is_limited, is_first_breach
    except Exception:
        # Fall back to in-memory if DB call fails or table not yet created
        pass
    return None


def is_rate_limited(key, limit, window_seconds):
    """
    Returns (is_limited, is_first_breach).
    """
    # If in testing mode and tests don't explicitly request rate limiting
    if current_app.config.get("TESTING") and not current_app.config.get("ENABLE_RATE_LIMIT_TESTS"):
        return False, False

    # Attempt shared DB check
    result = _is_rate_limited_db(key, limit, window_seconds)
    if result is not None:
        return result

    # In-memory fallback
    return _is_rate_limited_memory(key, limit, window_seconds)


def clear_rate_limits():
    """Helper for test reset."""
    with _mem_lock:
        _mem_store.clear()


def rate_limit(limit=5, window_seconds=60, action_name="rate_limit"):
    """Decorator to rate limit route handlers per client IP."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if current_app.config.get("TESTING") and not current_app.config.get("ENABLE_RATE_LIMIT_TESTS"):
                return f(*args, **kwargs)

            # Client IP is trusted because ProxyFix is configured with x_for=1
            ip = request.remote_addr or "127.0.0.1"
            key = f"{action_name}:{ip}"
            limited, first_breach = is_rate_limited(key, limit, window_seconds)

            if limited:
                # Anti-flooding: Only emit an audit row on the INITIAL breach of the window
                if first_breach:
                    audit(
                        "rate_limit",
                        "denied",
                        path=request.path,
                        ip=ip,
                        action_attempted=action_name,
                        limit=limit,
                        window=window_seconds,
                    )
                resp = render_template(
                    "error.html",
                    msg="Too many requests. Please wait a moment and try again."
                )
                return resp, 429, {"Retry-After": str(window_seconds)}
            return f(*args, **kwargs)
        return wrapper
    return decorator
