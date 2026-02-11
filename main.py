#!/usr/bin/env python3
import argparse
import ipaddress
import json
import threading
import time
import msgpack
import struct
import queue
import os
import signal
import subprocess
import atexit
from typing import Optional, Tuple, List
from dataclasses import dataclass
from urllib.parse import urlparse
from event_names import HashToEventName, EventNameToHash
import gui as gui
from net_forwarder import run_tcp_proxy, intercept_client_oob, intercept_server_oob
from PySide6.QtWidgets import QApplication, QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton

import enet

MAGIC4 = b"\xFF\xFF\xFF\xFF"

LISTEN_PORT = 40000
CHANNEL_COUNT = 2

LAST_EVENT_ID = 0
LAST_NETGAME_TARGETS: List[int] = []

_ACTIVE_MITM: Optional["EnetMitm"] = None
_SHUTDOWN_STARTED = False


def _reset_mitm_state() -> None:
    mitm = _ACTIVE_MITM
    if mitm is None:
        return
    mitm.reset_state()


def _enqueue_gui_command(cmd: dict) -> None:
    mitm = _ACTIVE_MITM
    if mitm is None:
        print(f"[GUI] Command ignored (no active mitm): {cmd}")
        return
    mitm.enqueue_gui_command(cmd)


def _kill_fivem_processes() -> None:
    try:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Process -Name 'FiveM*' -ErrorAction SilentlyContinue | Stop-Process -Force -PassThru | Out-Null",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def _request_shutdown() -> None:
    global _SHUTDOWN_STARTED
    if _SHUTDOWN_STARTED:
        return
    _SHUTDOWN_STARTED = True
    _reset_mitm_state()
    _kill_fivem_processes()
    try:
        gui.request_quit()
    except Exception:
        pass


def _parse_gui_payload(payload_text: str):
    if payload_text is None:
        return None
    if not isinstance(payload_text, str):
        return payload_text
    cleaned = payload_text.strip()
    if not cleaned:
        return None
    try:
        return json.loads(cleaned)
    except Exception:
        return payload_text


def _parse_gui_hex(hex_text: str) -> Optional[bytes]:
    if not hex_text:
        return None
    if not isinstance(hex_text, str):
        return None
    cleaned = hex_text.replace(" ", "").strip()
    if not cleaned:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def parse_ip_port(s: str) -> Tuple[str, int]:
    s = s.strip()
    if ":" not in s:
        raise argparse.ArgumentTypeError(f"Address must be IP:PORT, got {s!r}")
    host, port_str = s.rsplit(":", 1)
    try:
        ipaddress.ip_address(host)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"IP invalid: {host!r} ({e})")
    try:
        port = int(port_str)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Port is not an int: {port_str!r}")
    if not (1 <= port <= 65535):
        raise argparse.ArgumentTypeError(f"Port must be 1..65535, got {port}")
    return host, port


def _normalize_cfx_input(value: str) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        return ""

    lower_cleaned = cleaned.lower()
    if lower_cleaned.startswith("http://") or lower_cleaned.startswith("https://"):
        parsed = urlparse(cleaned)
        path = (parsed.path or "").strip("/")
        if path.lower().startswith("join/"):
            parts = path.split("/", 1)
            return parts[1].strip() if len(parts) > 1 else ""
        return path

    if lower_cleaned.startswith("cfx.re/"):
        cleaned = cleaned[len("cfx.re/"):]
    if cleaned.lower().startswith("join/"):
        cleaned = cleaned[5:]

    return cleaned.strip().strip("/")


class LauncherDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_upstream: Optional[Tuple[str, int]] = None
        self.setWindowTitle("NetCheat Connect")
        self.setMinimumWidth(460)

        layout = QFormLayout(self)

        cfx_row = QHBoxLayout()
        cfx_row.setContentsMargins(0, 0, 0, 0)
        self.cfx_input = QLineEdit(self)
        self.cfx_input.setPlaceholderText("cfx code or cfx.re/join/...")
        self.resolve_btn = QPushButton("RESOLVE", self)
        self.resolve_btn.clicked.connect(self._on_resolve)
        cfx_row.addWidget(self.cfx_input)
        cfx_row.addWidget(self.resolve_btn)
        layout.addRow(QLabel("CFX.RE/", self), cfx_row)

        ip_row = QHBoxLayout()
        ip_row.setContentsMargins(0, 0, 0, 0)
        self.ip_input = QLineEdit(self)
        self.ip_input.setPlaceholderText("127.0.0.1:30120")
        self.connect_btn = QPushButton("CONNECT", self)
        self.connect_btn.clicked.connect(self._on_connect)
        ip_row.addWidget(self.ip_input)
        ip_row.addWidget(self.connect_btn)
        layout.addRow(QLabel("IP:", self), ip_row)

        self.connect_btn.setDefault(True)

    def _on_resolve(self) -> None:
        cfx_value = _normalize_cfx_input(self.cfx_input.text())
        if not cfx_value:
            QMessageBox.warning(self, "Resolve error", "Enter a valid CFX id or cfx.re/join URL.")
            return

        try:
            import get_ip_from_cfx
        except Exception as exc:
            QMessageBox.critical(self, "Resolve error", f"Failed to import get_ip_from_cfx.py:\n{exc}")
            return

        try:
            resolved = get_ip_from_cfx.get_ip(cfx_value)
        except Exception as exc:
            QMessageBox.critical(self, "Resolve error", f"Failed to resolve CFX endpoint:\n{exc}")
            return

        try:
            host, port = parse_ip_port(str(resolved))
        except argparse.ArgumentTypeError as exc:
            QMessageBox.critical(self, "Resolve error", f"Resolver returned invalid endpoint:\n{exc}")
            return

        self.ip_input.setText(f"{host}:{port}")

    def _on_connect(self) -> None:
        raw = self.ip_input.text().strip()
        if not raw:
            QMessageBox.warning(self, "Connect error", "Enter an IP:PORT endpoint.")
            return
        try:
            self.selected_upstream = parse_ip_port(raw)
        except argparse.ArgumentTypeError as exc:
            QMessageBox.critical(self, "Connect error", str(exc))
            return
        self.accept()


def _pick_upstream_via_launcher() -> Optional[Tuple[str, int]]:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    dialog = LauncherDialog()
    if dialog.exec() == QDialog.Accepted:
        return dialog.selected_upstream
    return None

def log_enet(tag: str, payload: bytes, *, flags: Optional[int] = None, channel: Optional[int] = None) -> None:
    global LAST_EVENT_ID, LAST_NETGAME_TARGETS
    if len(payload) < 4:
        print(f"[{tag}] <short> (len={len(payload)})", flush=True)
        return
    msg_type = int.from_bytes(payload[:4], "little", signed=False)
    name = HashToEventName(msg_type)
    if name=="msgPackedClones": return
    if name=="msgPackedAcks": return
    if name=="msgFrame": return
    if name=="msgEnd": return
    if name=="msgRoute": return
    if name=="msgArrayUpdate": return
    if name=="msgWorldGrid3": return
    if name=="msgIQuit":
        _reset_mitm_state()
    offset = 4
    event_data = None
    if name=="msgNetEvent" or name=="msgServerEvent":
        if name=="msgNetEvent":
            sourceNetId = struct.unpack('<H', payload[offset:offset+2])[0] # this is currently always -1, but may change
            offset+=2

        # Event name length: little-endian uint16
        name_len = struct.unpack('<H', payload[offset:offset+2])[0]
        offset += 2
        # Event name (null-terminated string)
        event_name_bytes = payload[offset:offset+name_len]
        event_name = event_name_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        offset += name_len
        event_data_bytes = payload[offset:]
        try:
            event_data = msgpack.unpackb(event_data_bytes)
        except msgpack.exceptions.ExtraData as e:
            event_data = e.unpacked
        except:
            event_data = event_data_bytes.hex()
        print(payload.hex())
        print(f"[{tag}]", event_name, event_data)
        result = {
            "packet_type": hex(msg_type),
            "event_type": name,
            "event_name": event_name,
            "event_data": event_data,
            "raw_event_data": event_data_bytes.hex(),
        }
        if "(gui)" not in tag: gui.send_event_to_gui(result, "OUT" if "C->S" in tag else "IN")
    elif name=="msgNetGameEventV2":
        # eventNameHash (u32), eventId (u16), isReply (u8), data (rest)
        if "S->C" in tag:
            # ServerNetGameEventV2: clientNetId (u16)
            clientNetId = struct.unpack_from('<H', payload, offset)[0]
            offset += 2
            targetPlayers = None
        else:
            # ClientNetGameEventV2: targetPlayers (SmallBytesArray => u8 count + u16[count])
            target_count = payload[offset]
            offset += 1
            targetPlayers = list(struct.unpack_from('<' + 'H' * target_count, payload, offset))
            offset += 2 * target_count
            clientNetId = None

        eventNameHash = struct.unpack_from('<I', payload, offset)[0]
        eventName = HashToEventName(eventNameHash)
        offset += 4
        eventId = struct.unpack_from('<H', payload, offset)[0]
        LAST_EVENT_ID = eventId
        offset += 2
        isReply = payload[offset] != 0  # bool stored as 1 byte
        offset += 1

        data = payload[offset:]  # ConstrainedStreamTail<0, 1025>
        print(payload.hex())
        print(f"[{tag}]", eventName, eventId, isReply, f"data={data}", f"clientNetId={clientNetId}", f"targetPlayers={targetPlayers}")
        if isinstance(targetPlayers, list):
            LAST_NETGAME_TARGETS = targetPlayers
        result = {
            "packet_type": hex(msg_type),
            "event_type": name,
            "event_name": eventName,
            "event_data": {
                "event_id": eventId,
                "is_reply": isReply,
                "client_net_id": clientNetId,
                "target_players": targetPlayers,
                "data_hex": data.hex(),
            },
            "raw_event_data": data.hex(),
        }
        if "(gui)" not in tag:
            gui.send_event_to_gui(result, "OUT" if "C->S" in tag else "IN")
    else: print(f"[{tag}] {name} (len={len(payload)})", flush=True)


@dataclass
class PendingPacket:
    data: bytes
    flags: int
    channel: int


class EnetMitm:
    def __init__(self, server_host: str, server_port: int) -> None:
        global _ACTIVE_MITM
        self.server_addr = enet.Address(server_host.encode("utf-8"), server_port)

        self.client_host = enet.Host(enet.Address(None, LISTEN_PORT), 1, CHANNEL_COUNT, 0, 0)
        self.server_host = enet.Host(None, 1, CHANNEL_COUNT, 0, 0)

        self.client_host.intercept = self._intercept_client
        self.server_host.intercept = self._intercept_server

        self.client_peer: Optional[enet.Peer] = None
        self.server_peer: Optional[enet.Peer] = None
        self.client_addr: Optional[enet.Address] = None
        self.connect_data: int = 0
        self.pending: List[PendingPacket] = []
        self._l_was_down = False
        self._gui_commands: "queue.Queue[dict]" = queue.Queue()
        _ACTIVE_MITM = self

    def reset_state(self) -> None:
        global LAST_EVENT_ID, LAST_NETGAME_TARGETS
        if self.client_peer is not None:
            try:
                self.client_peer.disconnect_now(0)
            except OSError:
                pass
            self.client_peer = None
        if self.server_peer is not None:
            try:
                self.server_peer.disconnect_now(0)
            except OSError:
                pass
            self.server_peer = None
        LAST_EVENT_ID = 0
        LAST_NETGAME_TARGETS = []
        self.client_addr = None
        self.connect_data = 0
        self.pending.clear()

    def _intercept_client(self, address: enet.Address, data: bytes) -> bool:
        return intercept_client_oob(
            address,
            data,
            magic4=MAGIC4,
            server_host=self.server_host,
            server_addr=self.server_addr,
            set_client_addr=self._set_client_addr,
        )

    def _intercept_server(self, address: enet.Address, data: bytes) -> bool:
        return intercept_server_oob(
            address,
            data,
            magic4=MAGIC4,
            client_host=self.client_host,
            get_client_addr=self._get_client_addr,
        )

    def _connect_upstream(self) -> None:
        if self.server_peer is not None:
            return
        self.server_peer = self.server_host.connect(self.server_addr, CHANNEL_COUNT, self.connect_data)
        print(f"[ENET] Connecting to upstream {self.server_addr.host}:{self.server_addr.port}", flush=True)

    def _is_connected(self, peer: Optional[enet.Peer]) -> bool:
        return peer is not None and peer.state == enet.PEER_STATE_CONNECTED

    def _forward(self, peer: enet.Peer, payload: bytes, flags: int, channel: int, tag: str) -> None:
        allowed = enet.PACKET_FLAG_RELIABLE | enet.PACKET_FLAG_UNSEQUENCED | enet.PACKET_FLAG_UNRELIABLE_FRAGMENT
        fwd_flags = flags & allowed
        pkt = enet.Packet(payload, fwd_flags)
        peer.send(channel, pkt)
        log_enet(tag, payload, flags=flags, channel=channel)

    def _next_event_id(self) -> int:
        global LAST_EVENT_ID
        LAST_EVENT_ID = (LAST_EVENT_ID + 1) & 0xFFFF
        return LAST_EVENT_ID

    def _build_netgame_event_v2(
        self,
        event_name: str,
        data: bytes,
        *,
        is_reply: bool = False,
        target_players: Optional[List[int]] = None,
    ) -> bytes:
        event_name_hash = EventNameToHash(event_name)
        if event_name_hash is None:
            raise ValueError(f"Unknown event name: {event_name}")
        event_id = self._next_event_id()
        msg_type = EventNameToHash("msgNetGameEventV2")
        if msg_type is None:
            raise ValueError("Missing msgNetGameEventV2 hash")
        targets = target_players or []
        if len(targets) > 255:
            raise ValueError("Too many target players (max 255).")
        return b"".join(
            (
                struct.pack("<I", msg_type),
                struct.pack("<B", len(targets)),
                b"".join(struct.pack("<H", t & 0xFFFF) for t in targets),
                struct.pack("<I", event_name_hash),
                struct.pack("<H", event_id),
                struct.pack("<B", 1 if is_reply else 0),
                data,
            )
        )

    def _build_net_event(
        self,
        event_name: str,
        event_data,
        source_net_id: int = 0xFFFF,
        msg_type_name: str = "msgServerEvent",
    ) -> bytes:
        msg_type = EventNameToHash(msg_type_name)
        name_bytes = (event_name + "\x00").encode("utf-8")

        if isinstance(event_data, (bytes, bytearray, memoryview)):
            data = bytes(event_data)
        else:
            # event_data should be the args array (list/tuple), not a string repr
            data = msgpack.packb(event_data, use_bin_type=True, strict_types=True)

        parts = [struct.pack("<I", msg_type)]
        if msg_type_name == "msgNetEvent":
            parts.append(struct.pack("<H", source_net_id & 0xFFFF))
        elif msg_type_name != "msgServerEvent":
            raise ValueError(f"Unsupported msg_type_name: {msg_type_name}")

        parts.extend((struct.pack("<H", len(name_bytes)), name_bytes, data))
        return b"".join(parts)

    def _set_client_addr(self, address: enet.Address) -> None:
        self.client_addr = address

    def _get_client_addr(self) -> Optional[enet.Address]:
        return self.client_addr

    def enqueue_gui_command(self, cmd: dict) -> None:
        self._gui_commands.put(cmd)

    def _handle_gui_command(self, cmd: dict) -> None:
        global LAST_NETGAME_TARGETS
        command = (cmd.get("command") or "").lower()
        if command not in {"send", "resend"}:
            print(f"[GUI] Unknown command: {cmd}")
            return
        name = cmd.get("name")
        if not name:
            print(f"[GUI] Missing event name: {cmd}")
            return
        direction = (cmd.get("direction") or "OUT").upper()
        event_type = cmd.get("event_type") or ("msgServerEvent" if direction == "OUT" else "msgNetEvent")
        raw_bytes = _parse_gui_hex(cmd.get("raw_hex", ""))
        try:
            if event_type == "msgNetGameEventV2":
                if direction == "IN":
                    print("[GUI] msgNetGameEventV2 IN send is not supported yet.")
                    return
                if raw_bytes is None:
                    payload_text = cmd.get("payload_utf8", "")
                    if payload_text is None:
                        data = b""
                    else:
                        data = _parse_gui_hex(payload_text)
                        if data is None and str(payload_text).strip():
                            print("[GUI] msgNetGameEventV2 payload must be hex.")
                            return
                        if data is None:
                            data = b""
                else:
                    data = raw_bytes
                target_players = LAST_NETGAME_TARGETS
                payload = self._build_netgame_event_v2(
                    name,
                    data,
                    target_players=target_players,
                )
            else:
                event_data = raw_bytes if raw_bytes is not None else _parse_gui_payload(cmd.get("payload_utf8", ""))
                msg_type_name = "msgServerEvent" if direction == "OUT" else "msgNetEvent"
                if event_type in {"msgNetEvent", "msgServerEvent"}:
                    msg_type_name = event_type
                payload = self._build_net_event(name, event_data, msg_type_name=msg_type_name)
        except Exception as e:
            print(f"[GUI] Failed to build event: {e}")
            return

        if direction == "OUT":
            peer = self.server_peer
            tag = "ENET C->S (gui)"
        elif direction == "IN":
            peer = self.client_peer
            tag = "ENET S->C (gui)"
        else:
            print(f"[GUI] Unknown direction {direction!r}: {cmd}")
            return

        if not self._is_connected(peer):
            print(f"[GUI] Not connected for {direction} send.")
            return
        self._forward(peer, payload, enet.PACKET_FLAG_RELIABLE, 0, tag)

    def _drain_gui_commands(self) -> None:
        while True:
            try:
                cmd = self._gui_commands.get_nowait()
            except queue.Empty:
                break
            self._handle_gui_command(cmd)

    def _handle_client_event(self, event: enet.Event) -> None:
        if event.type == enet.EVENT_TYPE_CONNECT:
            if self.client_peer is not None and self.client_peer is not event.peer:
                event.peer.disconnect_now(0)
                return
            self.client_peer = event.peer
            self.client_addr = event.peer.address
            self.connect_data = event.data
            print(f"[ENET] Client connected {self.client_addr.host}:{self.client_addr.port}", flush=True)
            self._connect_upstream()
        elif event.type == enet.EVENT_TYPE_DISCONNECT:
            if event.peer is self.client_peer:
                print(f"[ENET] Client disconnected {self.client_addr.host}:{self.client_addr.port}", flush=True)
                self.client_peer = None
                self.client_addr = None
                self.pending.clear()
                if self.server_peer is not None:
                    self.server_peer.disconnect_now(0)
                    self.server_peer = None
        elif event.type == enet.EVENT_TYPE_RECEIVE:
            payload = bytes(event.packet.data)
            if self._is_connected(self.server_peer):
                self._forward(self.server_peer, payload, event.packet.flags, event.channelID, "ENET C->S")
            else:
                self.pending.append(PendingPacket(payload, event.packet.flags, event.channelID))
                log_enet("ENET C->S (queued)", payload, flags=event.packet.flags, channel=event.channelID)

    def _handle_server_event(self, event: enet.Event) -> None:
        if event.type == enet.EVENT_TYPE_CONNECT:
            self.server_peer = event.peer
            print(f"[ENET] Upstream connected {self.server_addr.host}:{self.server_addr.port}", flush=True)
            if self.pending:
                for pkt in self.pending:
                    self._forward(self.server_peer, pkt.data, pkt.flags, pkt.channel, "ENET C->S")
                self.pending.clear()
        elif event.type == enet.EVENT_TYPE_DISCONNECT:
            if event.peer is self.server_peer:
                print(f"[ENET] Upstream disconnected {self.server_addr.host}:{self.server_addr.port}", flush=True)
                self.server_peer = None
                self.pending.clear()
                if self.client_peer is not None:
                    self.client_peer.disconnect_now(0)
                    self.client_peer = None
                    self.client_addr = None
        elif event.type == enet.EVENT_TYPE_RECEIVE:
            payload = bytes(event.packet.data)
            if self._is_connected(self.client_peer):
                self._forward(self.client_peer, payload, event.packet.flags, event.channelID, "ENET S->C")

    def run(self) -> None:
        print(f"[ENET] Listening on UDP :{LISTEN_PORT}, forwarding to {self.server_addr.host}:{self.server_addr.port}", flush=True)
        try:
            while True:
                try:
                    while True:
                        event = self.client_host.service(0)
                        if event.type == enet.EVENT_TYPE_NONE:
                            break
                        self._handle_client_event(event)
                except OSError:
                    pass

                try:
                    while True:
                        event = self.server_host.service(0)
                        if event.type == enet.EVENT_TYPE_NONE:
                            break
                        self._handle_server_event(event)
                except OSError:
                    pass

                self.client_host.flush()
                self.server_host.flush()
                self._drain_gui_commands()
                time.sleep(0.001)
        except KeyboardInterrupt:
            pass


def main() -> int:
    atexit.register(_kill_fivem_processes)

    def _handle_sigint(signum, frame):
        print("[MAIN] Ctrl+C received, shutting down...", flush=True)
        _request_shutdown()

    signal.signal(signal.SIGINT, _handle_sigint)

    ap = argparse.ArgumentParser(description="FiveM ENet MiTM (TCP relay + ENet UDP with OOB passthrough).")
    ap.add_argument("upstream", nargs="?", help="Upstream IP:PORT")
    args = ap.parse_args()

    if args.upstream:
        try:
            upstream_ip, upstream_port = parse_ip_port(args.upstream)
        except argparse.ArgumentTypeError as exc:
            ap.error(str(exc))
    else:
        selected = _pick_upstream_via_launcher()
        if selected is None:
            return 0
        upstream_ip, upstream_port = selected

    tcp_thread = threading.Thread(
        target=run_tcp_proxy,
        args=(("0.0.0.0", LISTEN_PORT), (upstream_ip, upstream_port)),
        daemon=True,
    )
    tcp_thread.start()
    gui.register_command_handler(_enqueue_gui_command)
    enet_mitm = EnetMitm(upstream_ip, upstream_port)
    mitm_thread = threading.Thread(target=enet_mitm.run, daemon=True)
    mitm_thread.start()
    os.startfile(f"fivem://connect/127.0.0.1:{LISTEN_PORT}")
    try:
        return gui.start_gui()
    finally:
        _request_shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
