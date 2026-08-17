BLOCKED_NAMES = {
    "example:blocked-event",
}


def patch(event):
    if event.get("name") in BLOCKED_NAMES:
        return None
    return event
