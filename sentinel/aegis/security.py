"""Credential storage, signed session cookies, and CSRF protection."""
import base64
import hashlib
import hmac
import json
import secrets
import time


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Mot de passe trop court : 12 caractères minimum")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt$16384${salt.hex()}${digest.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, salt_hex, digest_hex = stored.split("$")
        if algorithm != "scrypt" or int(n) != 16384:
            return False
        candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(candidate, bytes.fromhex(digest_hex))
    except (ValueError, TypeError):
        return False


def sign_session(secret: str, ttl_seconds: int = 28800) -> tuple[str, str]:
    csrf = secrets.token_urlsafe(24)
    payload = {"exp": int(time.time()) + ttl_seconds, "csrf": csrf, "nonce": secrets.token_hex(12)}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    mac = hmac.new(bytes.fromhex(secret), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{mac}", csrf


def verify_session(secret: str, cookie: str | None) -> dict | None:
    if not cookie or len(cookie) > 2000 or "." not in cookie:
        return None
    try:
        encoded, mac = cookie.rsplit(".", 1)
        expected = hmac.new(bytes.fromhex(secret), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if not isinstance(payload, dict) or payload["exp"] <= time.time():
            return None
        if not isinstance(payload.get("csrf"), str):
            return None
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def sha_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
