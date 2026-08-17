"""Built-in middleware templates used by the GUI."""

EXAMPLES = {
    "Block event names": (
        "block_event_names.py",
        '''BLOCKED_NAMES = {
    "example:blocked-event",
}


def patch(event):
    if event.get("name") in BLOCKED_NAMES:
        return None
    return event
''',
    ),
    "Clamp numeric fields": (
        "clamp_numeric_fields.py",
        '''LIMITS = {
    "health": (0, 200),
    "speed": (0, 100),
}


def _clamp(value):
    if isinstance(value, list):
        return [_clamp(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            limits = LIMITS.get(str(key).lower())
            if limits and isinstance(item, (int, float)) and not isinstance(item, bool):
                item = max(limits[0], min(limits[1], item))
            result[key] = _clamp(item)
        return result
    return value


def patch(event):
    if event.get("direction") == "OUT":
        event["data"] = _clamp(event.get("data"))
    return event
''',
    ),
    "Randomize ANGLE fingerprints": (
        "randomize_angle.py",
        '''import secrets
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
''',
    ),
    "Redact outbound secrets": (
        "redact_outbound_secrets.py",
        '''SECRET_KEYS = {"authorization", "password", "passwd", "secret", "token"}


def _redact(value):
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if str(key).lower() in SECRET_KEYS else _redact(item)
            for key, item in value.items()
        }
    return value


def patch(event):
    if event.get("direction") == "OUT":
        event["data"] = _redact(event.get("data"))
    return event
''',
    ),
}
