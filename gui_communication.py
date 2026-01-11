import json
import os
import socket
import tempfile
import threading
import time

GUI_HOST = "127.0.0.1"
PORT_FILE_ENV = "EVENT_INSPECTOR_PORT_FILE"
DEFAULT_PORT_FILE = "inspector_port.txt"

_gui_sock = None
_gui_lock = threading.Lock()


def _safe_json(value):
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _port_file_candidates():
    env_path = os.environ.get(PORT_FILE_ENV)
    if env_path:
        return [env_path]
    return [
        os.path.join(tempfile.gettempdir(), DEFAULT_PORT_FILE),
        DEFAULT_PORT_FILE,
        os.path.join("qt_event_inspector", DEFAULT_PORT_FILE),
    ]


def _read_gui_port():
    for path in _port_file_candidates():
        try:
            with open(path, "r", encoding="ascii") as f:
                data = f.read().strip()
            if not data:
                continue
            return int(data)
        except (FileNotFoundError, ValueError, OSError):
            continue
    return None


def _connect_to_gui():
    global _gui_sock
    port = _read_gui_port()
    if port is None:
        return None
    try:
        sock = socket.create_connection((GUI_HOST, port), timeout=1.0)
    except OSError:
        return None
    sock.settimeout(None)
    _gui_sock = sock
    return sock


def send_event_to_gui(result, direction, src=None, dst=None):
    global _gui_sock
    payload = {
        "type": "event",
        "direction": direction,
        "name": result.get("event_name", ""),
        "payload": _safe_json(result.get("event_data")),
        "raw_hex": result.get("raw_event_data", ""),
        "status": "captured",
        "packet_type": result.get("packet_type"),
        "src": src,
        "dst": dst,
    }
    data = json.dumps(payload).encode("utf-8") + b"\n"
    with _gui_lock:
        if _gui_sock is None:
            _connect_to_gui()
        if _gui_sock is None:
            return
        try:
            _gui_sock.sendall(data)
        except Exception as e:
            print(f"Failed to send event to GUI: {e}")
            try:
                _gui_sock.close()
            except Exception:
                pass
            _gui_sock = None


def _listen_for_gui_commands():
    global _gui_sock
    pending = b""
    while True:
        with _gui_lock:
            if _gui_sock is None:
                _connect_to_gui()
            sock = _gui_sock
        if sock is None:
            time.sleep(0.5)
            continue
        try:
            data = sock.recv(4096)
            if not data:
                with _gui_lock:
                    if _gui_sock is sock:
                        _gui_sock.close()
                        _gui_sock = None
                pending = b""
                continue
        except Exception:
            with _gui_lock:
                if _gui_sock is sock:
                    try:
                        _gui_sock.close()
                    except Exception:
                        pass
                    _gui_sock = None
            pending = b""
            continue

        pending += data
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                cmd = json.loads(line.decode("utf-8", errors="replace"))
            except Exception as e:
                print(f"Invalid GUI command payload: {e}")
                continue
            print(f"GUI command: {cmd}")


def start_command_listener():
    thread = threading.Thread(target=_listen_for_gui_commands, daemon=True)
    thread.start()
    return thread
