"""A stand-in for DNSExit: its update API (POST, JSON, the key in the apikey header) and an authoritative nameserver
(UDP, A and NS records) that answers what the API last wrote. Used by test_dnsexit_script.py, test_showcase_role.py and
tests/panel/test_domain.py.

    dns = MockDNSExit(key="test-key"); dns.start(); ...; dns.stop()
    other = MockDNSExit(host="127.0.0.3", port=int(dns.nameserver.rsplit(":", 1)[1])).start()

State: records {name: [ip, ...]} (A records), ns {name: [nameserver name, ...]} (NS records; a name in neither is
NXDOMAIN), posts (every POST body, with the header key), refuse (an API answer to give instead of success, e.g.
{"code": 2, "message": "API Key Authentication Error"}), silent (the nameserver drops every query), servfail (it answers
SERVFAIL, as DNSExit's ns1 does for a zone that other nameservers of theirs serve), authoritative (False: answers
without the AA flag, as a resolver or a cache does; with RA set), queries (how many it got). host and port pick the
nameserver's address (several stand-ins on one port, as real nameservers all on 53).
"""

import json
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockDNSExit:
    def __init__(self, key="test-key", zone="example.test", host="127.0.0.1", port=0):
        self.key, self.zone, self.host, self.port = key, zone, host, port
        self.records, self.ns, self.posts = {}, {}, []
        self.refuse, self.silent, self.servfail, self.authoritative = None, False, False, True
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
            records, servers = self.records.get(name), self.ns.get(name)
        flags = 0x8400 if self.authoritative else 0x8080
        if self.servfail:
            return struct.pack(">HHHHHH", qid, flags & 0xFBFF | 0x0002, 1, 0, 0, 0) + question
        if records is None and servers is None:
            return struct.pack(">HHHHHH", qid, flags | 0x0003, 1, 0, 0, 0) + question
        answers = b""
        count = 0
        if qtype == 1:
            for ip in records or []:
                answers += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
                count += 1
        if qtype == 2:
            for server in servers or []:
                rdata = b"".join(bytes([len(label)]) + label.encode() for label in server.split(".")) + b"\0"
                answers += struct.pack(">HHHIH", 0xC00C, 2, 1, 3600, len(rdata)) + rdata
                count += 1
        return struct.pack(">HHHHHH", qid, flags, qdcount, count, 0, 0) + question + answers

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
        self.udp.bind((self.host, self.port))
        threading.Thread(target=self._serve_dns, daemon=True).start()
        self.api_url = f"http://127.0.0.1:{self.http.server_address[1]}/dns/"
        self.nameserver = f"{self.host}:{self.udp.getsockname()[1]}"
        return self

    def stop(self):
        self._stopping = True
        self.http.shutdown()
        self.http.server_close()
        self.udp.close()
