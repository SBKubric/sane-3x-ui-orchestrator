#!/usr/bin/env python3
"""Stand-in for xray in tests of neighbour.py's handshake check: `fake_xray.py run -c <config>`.

A config with a VLESS inbound is "the Reality server": it listens on the inbound's port, reads "host:port\\n" from
each connection and relays to it, unless the inbound's Reality target is listed in $FAKE_XRAY_BROKEN (comma
separated), which closes every connection, like a Reality handshake that never completes. A config with a SOCKS
inbound is "the client": a SOCKS5 server that hands every CONNECT to the server of its VLESS outbound. Each config is
copied to $FAKE_XRAY_RECORD/<inbound protocol>.json when that is set.
"""

import json
import os
import socket
import sys
import threading


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def relay(a, b):
    threading.Thread(target=pipe, args=(a, b), daemon=True).start()
    pipe(b, a)


def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise OSError("closed")
        data += chunk
    return data


def server(inbound, conn):
    with conn:
        line = b""
        while not line.endswith(b"\n"):
            line += recv_exact(conn, 1)
        target = inbound["streamSettings"]["realitySettings"]["target"]
        if target in os.environ.get("FAKE_XRAY_BROKEN", "").split(","):
            return
        host, _, port = line.decode().strip().rpartition(":")
        with socket.create_connection((host, int(port)), timeout=10) as upstream:
            relay(conn, upstream)


def client(outbound, conn):
    with conn:
        recv_exact(conn, 2)
        conn.recv(255)
        conn.sendall(b"\x05\x00")
        head = recv_exact(conn, 4)
        if head[3] == 3:
            host = recv_exact(conn, recv_exact(conn, 1)[0]).decode()
        else:
            host = socket.inet_ntoa(recv_exact(conn, 4))
        port = int.from_bytes(recv_exact(conn, 2), "big")
        vnext = outbound["settings"]["vnext"][0]
        with socket.create_connection((vnext["address"], vnext["port"]), timeout=10) as upstream:
            upstream.sendall(f"{host}:{port}\n".encode())
            conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            relay(conn, upstream)


def main():
    config = json.load(open(sys.argv[sys.argv.index("-c") + 1]))
    inbound = config["inbounds"][0]
    if os.environ.get("FAKE_XRAY_RECORD"):
        with open(os.path.join(os.environ["FAKE_XRAY_RECORD"], inbound["protocol"] + ".json"), "w") as out:
            json.dump(config, out)
    listener = socket.create_server((inbound["listen"], inbound["port"]))
    while True:
        conn, _ = listener.accept()
        if inbound["protocol"] == "vless":
            threading.Thread(target=server, args=(inbound, conn), daemon=True).start()
        else:
            threading.Thread(target=client, args=(config["outbounds"][0], conn), daemon=True).start()


if __name__ == "__main__":
    main()
