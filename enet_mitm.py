import argparse
import socket
import struct
import sys
import time

import msgpack

from rage_hash import RAGEHash
import gui_communication as gui

try:
    import enet
except Exception as exc:
    print(f"ENet module missing: {exc}")
    print("Install python-enet/pyenet to run this script.")
    sys.exit(1)


SUPPORTED_EVENTS = {
    "msgServerEvent": RAGEHash("msgServerEvent"),
    "msgNetEvent": RAGEHash("msgNetEvent"),
}


def parse_client_server_event(payload):
    try:
        if len(payload) < 6:
            return None

        offset = 0
        packet_type = struct.unpack("<I", payload[offset : offset + 4])[0]
        offset += 4

        if packet_type not in SUPPORTED_EVENTS.values():
            return None

        if packet_type == SUPPORTED_EVENTS["msgNetEvent"]:
            if offset + 2 > len(payload):
                return None
            offset += 2

        if offset + 2 > len(payload):
            return None

        name_len = struct.unpack("<H", payload[offset : offset + 2])[0]
        offset += 2
        if offset + name_len > len(payload):
            return None

        event_name_bytes = payload[offset : offset + name_len]
        event_name = event_name_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        offset += name_len

        event_data_bytes = payload[offset:]
        try:
            event_data = msgpack.unpackb(event_data_bytes)
        except msgpack.exceptions.ExtraData as e:
            event_data = e.unpacked
        except Exception:
            event_data = event_data_bytes.hex()

        return {
            "packet_type": hex(packet_type),
            "event_name": event_name,
            "event_data": event_data,
            "raw_event_data": event_data_bytes.hex(),
        }
    except Exception as exc:
        print(f"Error parsing packet: {exc}")
        return None


def addr_to_str(host_value, port):
    if hasattr(host_value, "host"):
        host_value = host_value.host
    if isinstance(host_value, (bytes, bytearray)):
        return f"{socket.inet_ntoa(host_value)}:{port}"
    if isinstance(host_value, str):
        return f"{host_value}:{port}"
    return f"{socket.inet_ntoa(struct.pack('!I', int(host_value)))}:{port}"


def send_gui_packet(payload, direction, src, dst):
    result = parse_client_server_event(payload)
    if result is None:
        return
    gui.send_event_to_gui(result, direction, src=src, dst=dst)


def print_iptables(upstream_host, upstream_port, listen_port, client_port):
    print("\niptables rules (example, run as root):")
    print(
        "  sudo iptables -t nat -A OUTPUT -p udp "
        f"-d {upstream_host} --dport {upstream_port} -j REDIRECT --to-ports {listen_port}"
    )
    print(
        "  sudo iptables -t nat -A PREROUTING -p udp "
        f"-s {upstream_host} --sport {upstream_port} "
        f"-j REDIRECT --to-ports {client_port}"
    )
    print()


def main():
    parser = argparse.ArgumentParser(description="ENet MiTM proxy (client+server)")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=50121)
    parser.add_argument("--client-host", default="0.0.0.0")
    parser.add_argument("--client-port", type=int, default=50122)
    parser.add_argument("--upstream-host", required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--channels", type=int, default=2)
    args = parser.parse_args()

    gui.start_command_listener()

    print_iptables(args.upstream_host, args.upstream_port, args.listen_port, args.client_port)

    server_addr = enet.Address(args.listen_host.encode("ascii"), args.listen_port)
    server_host = enet.Host(server_addr, 1, args.channels, 0, 0)

    client_addr = enet.Address(args.client_host.encode("ascii"), args.client_port)
    try:
        client_host = enet.Host(client_addr, 1, args.channels, 0, 0)
    except Exception as exc:
        print("Failed to bind ENet client host.")
        print(f"Requested local bind: {args.client_host}:{args.client_port}")
        print(f"Channels: {args.channels}")
        print(f"Exception: {exc!r}")
        if args.client_port == 0:
            print("Note: some ENet bindings do not accept port 0 for ephemeral binds.")
        sys.exit(1)

    upstream_addr = enet.Address(args.upstream_host.encode("ascii"), args.upstream_port)

    client_peer = None
    upstream_peer = None
    client_endpoint_logged = False

    print(
        f"ENet MiTM: listen {args.listen_host}:{args.listen_port} "
        f"-> upstream {args.upstream_host}:{args.upstream_port}"
    )

    try:
        while True:
            event = server_host.service(10)
            while event.type != enet.EVENT_TYPE_NONE:
                if event.type == enet.EVENT_TYPE_CONNECT:
                    client_peer = event.peer
                    client_endpoint_logged = False
                    if upstream_peer is None:
                        upstream_peer = client_host.connect(upstream_addr, args.channels)
                    print("Client connected to MiTM server.")
                elif event.type == enet.EVENT_TYPE_RECEIVE:
                    if not client_endpoint_logged:
                        client_endpoint_logged = True
                        print(
                            "Client endpoint: "
                            f"{addr_to_str(event.peer.address.host, event.peer.address.port)}"
                        )
                    payload = bytes(event.packet.data)
                    src = addr_to_str(event.peer.address.host, event.peer.address.port)
                    dst = f"{args.upstream_host}:{args.upstream_port}"
                    send_gui_packet(payload, "OUT", src, dst)
                    if upstream_peer is not None:
                        pkt = enet.Packet(event.packet.data, event.packet.flags)
                        upstream_peer.send(event.channelID, pkt)
                    try:
                        event.packet.destroy()
                    except Exception:
                        pass
                elif event.type == enet.EVENT_TYPE_DISCONNECT:
                    print("Client disconnected.")
                    if upstream_peer is not None:
                        upstream_peer.disconnect()
                    client_peer = None
                    upstream_peer = None
                event = server_host.service(0)

            try:
                event = client_host.service(0)
            except OSError as exc:
                print("Upstream service error.")
                print(f"Exception: {exc!r}")
                print(f"Client bind: {args.client_host}:{args.client_port}")
                print(f"Upstream: {args.upstream_host}:{args.upstream_port}")
                print(f"Upstream peer present: {upstream_peer is not None}")
                print(f"Client peer present: {client_peer is not None}")
                time.sleep(0.2)
                continue
            while event.type != enet.EVENT_TYPE_NONE:
                if event.type == enet.EVENT_TYPE_CONNECT:
                    print("Connected to upstream server.")
                elif event.type == enet.EVENT_TYPE_RECEIVE:
                    payload = bytes(event.packet.data)
                    src = f"{args.upstream_host}:{args.upstream_port}"
                    if client_peer is not None:
                        dst = addr_to_str(client_peer.address.host, client_peer.address.port)
                    else:
                        dst = "unknown"
                    send_gui_packet(payload, "IN", src, dst)
                    if client_peer is not None:
                        pkt = enet.Packet(event.packet.data, event.packet.flags)
                        client_peer.send(event.channelID, pkt)
                    try:
                        event.packet.destroy()
                    except Exception:
                        pass
                elif event.type == enet.EVENT_TYPE_DISCONNECT:
                    print("Upstream disconnected.")
                    if client_peer is not None:
                        client_peer.disconnect()
                    upstream_peer = None
                event = client_host.service(0)

            time.sleep(0.001)
    except KeyboardInterrupt:
        print("Shutting down ENet MiTM.")


if __name__ == "__main__":
    main()
