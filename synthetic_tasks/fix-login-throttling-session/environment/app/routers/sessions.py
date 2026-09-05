"""Session cookie helpers.

Deliberately weak: tokens come from the `random` PRNG and embed the username,
and the cookie helpers never set expiry attributes.
"""
import random

SESSION_COOKIE = "session"
REMEMBER_COOKIE = "remember"


def weak_session_token(username: str) -> str:
    # BUG: weak PRNG, ~20 bits of entropy, username suffix leaks identity
    return f"{random.randint(0, 10**6):06d}-{username}"


def set_session_cookie(response, token: str) -> None:
    # BUG: no expiry attributes, not httponly
    response.set_cookie(SESSION_COOKIE, token)
