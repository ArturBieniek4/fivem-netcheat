import secrets
import string


NEEDLE = "ANGLE ("
ALPHABET = string.ascii_letters + string.digits


def _random_text(length):
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def _rewrite(value):
    if isinstance(value, str):
        return _random_text(len(value)) if NEEDLE in value else value
    if isinstance(value, list):
        return [_rewrite(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_rewrite(item) for item in value)
    if isinstance(value, dict):
        return {key: _rewrite(item) for key, item in value.items()}
    return value


def patch(event):
    if event.get("direction") == "OUT":
        event["data"] = _rewrite(event.get("data"))
    return event
