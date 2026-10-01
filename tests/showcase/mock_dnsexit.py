"""A stand-in for DNSExit: its update API (POST, JSON, the key in the apikey header) and an authoritative nameserver
(UDP, A records only) that answers what the API last wrote. Used by test_dnsexit_script.py and test_showcase_role.py.

    dns = MockDNSExit(key="test-key"); dns.start(); ...; dns.stop()

State: records {name: [ip, ...]} (a missing name is NXDOMAIN), posts (every POST body, with the header key), refuse
(an API answer to give instead of success, e.g. {"code": 2, "message": "API Key Authentication Error"}), silent (the
nameserver drops every query), queries (how many it got).
"""

import json
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockDNSExit:
    def __init__(self, key="test-key", zone="example.test"):
        self.key, self.zone = key, zone
        self.records, self.posts = {}, []
        self.refuse, self.silent = None, False
        self.lock = threading.Lock()
        self.queries = 0

    # --- API -----------------------------------------------------------------------------------------------------
    def _handler(self):
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):  # noqa: N802
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                with mock.lock:
                    try:
                        body = json.loads(raw)
                    except ValueError:
                        return self._send({"code": 4, "message": "JSON Data Syntax Error"})
                    mock.posts.append({"apikey": self.headers.get("apikey"), "body": body})
                    if mock.refuse:
                        return self._send(mock.refuse)
                    if self.headers.get("apikey") != mock.key:
                        return self._send({"code": 2, "message": "API Key Authentication Error"})
                    if body.get("domain") != mock.zone or not isinstance(body.get("add"), dict):
                        return self._send({"code": 3, "message": "Missing Required Definitions"})
                    add = body["add"]
                    name = (add["name"] + "." if add.get("name") else "") + mock.zone
                    if add.get("overwrite"):
                        mock.records[name] = [add["content"]]
                    else:
                        mock.records.setdefault(name, []).append(add["content"])
                    return self._send({"code": 0, "message": "Success"})

            def _send(self, payload):
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler

    # --- nameserver ----------------------------------------------------------------------------------------------
    def _answer(self, packet):
        qid, _flags, qdcount = struct.unpack(">HHH", packet[:6])
        offset, labels = 12, []
        while packet[offset]:
            length = packet[offset]
            labels.append(packet[offset + 1:offset + 1 + length].decode())
            offset += 1 + length
        offset += 1
        qtype, _qclass = struct.unpack(">HH", packet[offset:offset + 4])
        question = packet[12:offset + 4]
        name = ".".join(labels).lower()
        with self.lock:
            self.queries += 1
            records = self.records.get(name)
        if records is None:
            return struct.pack(">HHHHHH", qid, 0x8403, 1, 0, 0, 0) + question
        answers = b""
        count = 0
        if qtype == 1:
            for ip in records:
                answers += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
                count += 1
        return struct.pack(">HHHHHH", qid, 0x8400, qdcount, count, 0, 0) + question + answers

    def _serve_dns(self):
        while not self._stopping:
            try:
                packet, peer = self.udp.recvfrom(4096)
            except OSError:
                return
            if self.silent:
                continue
            try:
                self.udp.sendto(self._answer(packet), peer)
            except (OSError, IndexError, struct.error):
                continue

    # --- life cycle ----------------------------------------------------------------------------------------------
    def start(self):
        self._stopping = False
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        threading.Thread(target=self._serve_dns, daemon=True).start()
        self.api_url = f"http://127.0.0.1:{self.http.server_address[1]}/dns/"
        self.nameserver = f"127.0.0.1:{self.udp.getsockname()[1]}"
        return self

    def stop(self):
        self._stopping = True
        self.http.shutdown()
        self.http.server_close()
        self.udp.close()
