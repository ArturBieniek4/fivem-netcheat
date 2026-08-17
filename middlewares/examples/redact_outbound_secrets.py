SECRET_KEYS = {"authorization", "password", "passwd", "secret", "token"}


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
