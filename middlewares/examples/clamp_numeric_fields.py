LIMITS = {
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
