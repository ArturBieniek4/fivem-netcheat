import select
import socket
import threading
from typing import Callable, Optional, Tuple


def tcp_pipe(
    client_sock: socket.socket,
    up_sock: socket.socket,
    client_addr: Tuple[str, int],
    upstream_addr: Tuple[str, int],
) -> None:
    try:
        client_sock.setblocking(False)
        up_sock.setblocking(False)

        while True:
            r, _, _ = select.select([client_sock, up_sock], [], [])
            for s in r:
                other = up_sock if s is client_sock else client_sock
                try:
                    data = s.recv(65536)
                except BlockingIOError:
                    continue
                if not data:
                    return

                view = memoryview(data)
                while view:
                    try:
                        n = other.send(view)
                        view = view[n:]
                    except BlockingIOError:
                        select.select([], [other], [])
    finally:
        try:
            client_sock.close()
        except OSError:
            pass
        try:
            up_sock.close()
        except OSError:
            pass


def run_tcp_proxy(
    listen: Tuple[str, int],
    upstream: Tuple[str, int],
) -> None:
    listen_ip, listen_port = listen
    upstream_ip, upstream_port = upstream

    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((listen_ip, listen_port))
    ls.listen(200)

    try:
        while True:
            print(f"[TCP] Waiting for client on :{listen_port}...", flush=True)
            client_sock, client_addr = ls.accept()

            up_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                up_sock.connect((upstream_ip, upstream_port))
            except OSError:
                client_sock.close()
                up_sock.close()
                continue

            print(f"[TCP] Connected {client_addr[0]}:{client_addr[1]} <-> {upstream_ip}:{upstream_port}", flush=True)

            t = threading.Thread(
                target=tcp_pipe,
                args=(client_sock, up_sock),
                kwargs=dict(
                    client_addr=client_addr,
                    upstream_addr=(upstream_ip, upstream_port),
                ),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            ls.close()
        except OSError:
            pass


def intercept_client_oob(
    address,
    data: bytes,
    *,
    magic4: bytes,
    server_host,
    server_addr,
    set_client_addr: Callable[[object], None],
) -> bool:
    if len(data) < 4 or data[:4] != magic4:
        return False

    set_client_addr(address)
    server_host.socket.send(server_addr, data)
    return True


def intercept_server_oob(
    address,
    data: bytes,
    *,
    magic4: bytes,
    client_host,
    get_client_addr: Callable[[], Optional[object]],
) -> bool:
    if len(data) < 4 or data[:4] != magic4:
        return False

    client_addr = get_client_addr()
    if client_addr is None:
        return True

    client_host.socket.send(client_addr, data)
    return True
