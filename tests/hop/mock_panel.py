"""Test double of the 3ax-ui panel API (SBKubric/3ax-ui-proxy v1.9.0-chain.5), for tests of roles hop and panel:
the chain registry (web/controller/chain_controller.go, web/service/chain_service.go) and, for role panel's
inbounds, the inbound API, the AmneziaWG server and the monitoring page data (see Panel below).

It keeps the parts the role depends on: the login cookie, the {success, msg, obj} envelope with refusals as
HTTP 200 + success false + "<code>: <detail>", strict JSON bodies (unknown fields and wrong types are HTTP 400),
0-based inner positions compacted after every change, next hops re-chained (inner N -> N-1, edges -> last
joined inner), pending/joined/legacy/draining, one-time join tokens, setActive and del refusals, draining of a
hop with live outer neighbours. Test-only extras: POST /test/join (what `x-ui chain rejoin` does on a box),
GET /test/state, POST /test/reset, GET /install.sh (the fake installer), and for the panel part
POST /test/panel/reset, POST /test/panel/ensure, POST /test/panel/targets.
"""

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

BASE = "/base/"
USER, PASSWORD = "admin", "secret-pass"
COOKIE = "3ax-ui=mock-session"
NAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


class Refusal(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code


class BadRequest(Exception):
    pass


class Registry:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset([])
        self.panel = Panel(self)

    def reset(self, hops):
        self.hops = []
        self.tokens = {}
        self.revision = 1
        self.next_id = 1
        self.calls = []
        self.issued = []
        for seed in hops:
            hop = self._new_hop(seed["name"], seed["host"], seed["role"], seed.get("subPort", 2096),
                                seed.get("subScheme", "https"))
            hop["state"] = seed.get("state", "joined")
            hop["isActive"] = seed.get("isActive", False)
            hop["position"] = seed.get("position", 0)
            self.hops.append(hop)
        self._reconcile()

    def _new_hop(self, name, host, role, sub_port, sub_scheme):
        hop = {"id": self.next_id, "name": name, "host": host, "role": role, "nextHopId": None, "position": 0,
               "subPort": sub_port, "subScheme": sub_scheme, "state": "pending", "isActive": False,
               "drainRevision": 0, "drainUntil": 0, "joinTokenExpires": 0, "observedAddr": "", "joinedAt": 0,
               "lastSeenAt": 0, "lastRevision": 0, "createdAt": 0, "updatedAt": 0}
        self.next_id += 1
        return hop

    def _inners(self):
        return sorted((h for h in self.hops if h["role"] == "inner"), key=lambda h: (h["position"], h["id"]))

    def _reconcile(self):
        previous, last_entered, position = None, None, 0
        for hop in self._inners():
            if hop["state"] == "draining":
                continue
            hop["position"], hop["nextHopId"] = position, previous
            position += 1
            previous = hop["id"]
            if hop["state"] in ("joined", "legacy"):
                last_entered = hop["id"]
        for hop in self.hops:
            if hop["role"] == "edge" and hop["state"] != "draining":
                hop["nextHopId"] = last_entered

    def ordered(self):
        inners = sorted((h for h in self.hops if h["role"] == "inner"),
                        key=lambda h: (h["position"], 0 if h["state"] == "draining" else 1, h["id"]))
        edges = sorted((h for h in self.hops if h["role"] == "edge"), key=lambda h: h["id"])
        return [dict(h) for h in inners + edges]

    def load(self, hop_id):
        for hop in self.hops:
            if hop["id"] == hop_id:
                return hop
        raise Refusal("unknown_hop", f"no hop with id {hop_id}")

    def _name_free(self, name, own_id=0):
        if any(h["name"] == name and h["id"] != own_id for h in self.hops):
            raise Refusal("name_taken", f"{name!r} is taken")

    @staticmethod
    def _valid(name=None, host=None, sub_port=None, sub_scheme=None):
        if name is not None and not (1 <= len(name) <= 32 and set(name) <= NAME_CHARS):
            raise Refusal("invalid_name", f"{name!r}")
        if host is not None and not host.strip():
            raise Refusal("invalid_host", "host must not be empty")
        if sub_port is not None and not 1 <= sub_port <= 65535:
            raise Refusal("invalid_sub_port", f"{sub_port}")
        if sub_scheme is not None and sub_scheme not in ("http", "https"):
            raise Refusal("invalid_sub_scheme", f"{sub_scheme!r}")

    def token_for(self, hop):
        token = secrets.token_hex(16)
        self.tokens[token] = hop["id"]
        self.issued.append(token)
        hop["joinTokenExpires"] = 1
        return token

    def add(self, body):
        sub_port = body.get("subPort") or 2096
        sub_scheme = body.get("subScheme") or "https"
        self._valid(body.get("name", ""), body.get("host", ""), sub_port, sub_scheme)
        if body.get("role") not in ("inner", "edge"):
            raise Refusal("invalid_role", repr(body.get("role")))
        self._name_free(body["name"])
        hop = self._new_hop(body["name"], body["host"].strip(), body["role"], sub_port, sub_scheme)
        if hop["role"] == "inner":
            inners = self._inners()
            position = body.get("position", len(inners))
            if position is None:
                position = len(inners)
            if not 0 <= position <= len(inners):
                raise Refusal("invalid_position", f"position {position} is outside 0..{len(inners)}")
            for other in inners:
                if other["position"] >= position:
                    other["position"] += 1
            hop["position"] = position
        self.hops.append(hop)
        self._reconcile()
        return {"hop": dict(hop), "joinToken": self.token_for(hop), "joinTokenExpires": 1}

    def update(self, hop_id, body):
        for field in ("role", "position", "state", "isActive", "nextHopId", "id"):
            if field in body:
                raise Refusal("field_immutable", f"{field!r} cannot be changed through update")
        hop = self.load(hop_id)
        if hop["state"] == "draining":
            raise Refusal("hop_not_joined", "draining")
        self._valid(body.get("name"), body.get("host"), body.get("subPort"), body.get("subScheme"))
        if "name" in body:
            self._name_free(body["name"], hop_id)
        changed = False
        for field in ("name", "host", "subPort", "subScheme"):
            if field in body and body[field] != hop[field]:
                hop[field], changed = body[field], True
        if changed:
            self.revision += 1

    def reissue(self, hop_id):
        hop = self.load(hop_id)
        if hop["state"] == "draining":
            raise Refusal("hop_not_joined", "draining")
        self.tokens = {t: i for t, i in self.tokens.items() if i != hop_id}
        hop["state"] = "pending"
        return {"joinToken": self.token_for(hop), "joinTokenExpires": 1}

    def set_active(self, hop_id):
        hop = self.load(hop_id)
        if hop["state"] == "draining":
            raise Refusal("hop_not_joined", "draining")
        if hop["role"] != "edge":
            raise Refusal("not_an_edge", hop["name"])
        if hop["state"] not in ("joined", "legacy"):
            raise Refusal("hop_not_joined", f"{hop['name']} is {hop['state']}")
        if hop["isActive"]:
            return
        for other in self.hops:
            other["isActive"] = False
        hop["isActive"] = True
        self.revision += 1

    def delete(self, hop_id, body):
        hop = self.load(hop_id)
        if hop["state"] == "draining" and not body.get("skipDrain"):
            return {"hop": hop["name"], "state": "draining"}
        if hop["isActive"]:
            others = [h for h in self.hops if h["id"] != hop_id and h["role"] == "edge"
                      and h["state"] in ("joined", "legacy")]
            if others:
                raise Refusal("active_edge_in_use", f"{hop['name']!r} is the active edge")
            if not body.get("force"):
                raise Refusal("active_edge_in_use", f"{hop['name']!r} is the last active edge, needs force")
        outer = [h for h in self.hops if h["nextHopId"] == hop_id and h["state"] in ("joined", "legacy")]
        if outer and not body.get("skipDrain"):
            hop["state"], hop["isActive"] = "draining", False
            for h in outer:
                h["nextHopId"] = hop["nextHopId"]
            self._reconcile()
            self.revision += 1
            return {"hop": hop["name"], "state": "draining"}
        self.hops.remove(hop)
        self.tokens = {t: i for t, i in self.tokens.items() if i != hop_id}
        for h in self.hops:
            if h["nextHopId"] == hop_id:
                h["nextHopId"] = hop["nextHopId"]
        self._reconcile()
        self.revision += 1
        return {"hop": hop["name"], "state": "deleted"}

    def join(self, token):
        hop_id = self.tokens.pop(token, None)
        if hop_id is None:
            raise Refusal("unknown_token", "unknown, expired or spent")
        hop = self.load(hop_id)
        hop["state"], hop["joinTokenExpires"] = "joined", 0
        self._reconcile()
        self.revision += 1
        return {"name": hop["name"], "role": hop["role"]}

    def listing(self):
        active = next((h["name"] for h in self.hops if h["isActive"]), "")
        return {"revision": self.revision, "activeEdge": active, "pollSeconds": 30, "hops": self.ordered(),
                "portsProblem": None, "draining": []}


PROBE_PREFIX = "probe-"
# model.Inbound as gin binds it (JSON): unknown fields are ignored, a wrong type is a binding error.
INBOUND_FIELDS = {"id": int, "up": int, "down": int, "total": int, "allTime": int, "remark": str, "enable": bool,
                  "expiryTime": int, "trafficReset": str, "lastTrafficResetTime": int, "clientStats": list,
                  "listen": str, "port": int, "protocol": str, "settings": str, "streamSettings": str, "tag": str,
                  "sniffing": str, "publicPort": int}
UPDATE_COPIED = ("up", "down", "total", "remark", "enable", "expiryTime", "trafficReset", "listen", "port", "protocol",
                 "settings", "streamSettings", "sniffing")
AWG_FIELDS = {"kind": str, "id": int, "enable": bool, "interfaceName": str, "listenPort": int, "mtu": int,
              "privateKey": str, "publicKey": str, "jc": int, "h1": str, "endpoint": str}


def bind(raw, fields):
    """Decodes a body the way gin's ShouldBind(JSON) does; a mismatch is a Refusal (the panel answers jsonMsg)."""
    try:
        body = json.loads(raw or "{}")
    except ValueError as err:
        raise Refusal("invalid_request", str(err)) from err
    if not isinstance(body, dict):
        raise Refusal("invalid_request", "not an object")
    for key, value in body.items():
        kind = fields.get(key)
        if kind is not None and value is not None and (not isinstance(value, kind)
                                                       or (kind is int and isinstance(value, bool))):
            raise Refusal("invalid_request", f"json: cannot unmarshal {type(value).__name__} into field {key}")
    return body


def clients_of(settings):
    try:
        return json.loads(settings or "{}").get("clients") or []
    except ValueError:
        return []


class Panel:
    """Inbounds, the AmneziaWG server and the monitoring page of the panel, with the behaviour role panel relies
    on: inbounds/add|update re-serialize settings (indented, client timestamps) when it has clients, refuse a
    new probe client, a taken port and a second AmneziaWG inbound; an AmneziaWG inbound is a bare record; the
    AWG server save takes the whole server and moves the AWG inbound to its port; a change of the relayed
    ports bumps the chain revision when the registry has hops (chainPortsChanged)."""

    def __init__(self, registry):
        self.registry = registry
        self.reset({})

    def reset(self, seed):
        self.inbounds = []
        self.next_id = 1
        self.x25519 = []
        self.targets = seed.get("targets")
        self.awg = {"kind": "awg", "id": 1, "enable": False, "interfaceName": "awg0", "listenPort": 38810, "mtu": 1420,
                    "privateKey": "awg-private-" + secrets.token_hex(8), "publicKey": "awg-public", "jc": 5,
                    "h1": "1-100", "endpoint": "10.0.0.1"}
        self.awg.update(seed.get("awg", {}))
        for inbound in seed.get("inbounds", []):
            self._store(dict(inbound))

    def _store(self, inbound):
        record = {"id": self.next_id, "up": 0, "down": 0, "total": 0, "allTime": 0, "remark": "", "enable": True,
                  "expiryTime": 0, "trafficReset": "never", "lastTrafficResetTime": 0, "clientStats": [],
                  "listen": "", "port": 0, "protocol": "", "settings": "", "streamSettings": "", "tag": "",
                  "sniffing": "", "publicPort": 0}
        record.update(inbound)
        record["id"] = self.next_id
        if not record["tag"]:
            record["tag"] = f"inbound-{record['port']}"
        self.next_id += 1
        self.inbounds.append(record)
        return record

    def load(self, inbound_id):
        for inbound in self.inbounds:
            if inbound["id"] == inbound_id:
                return inbound
        raise Refusal("record_not_found", f"inbound {inbound_id}")

    def ports(self):
        ports = sorted(i["port"] for i in self.inbounds if i["enable"] and i["protocol"] not in ("amneziawg", "nativewg"))
        if self.awg["enable"]:
            ports.append(self.awg["listenPort"])
        return sorted(ports)

    def _ports_changed(self):
        if self.registry.hops:
            self.registry.revision += 1

    @staticmethod
    def _reserialize(settings, old=None):
        """What InboundService does to settings with clients: MarshalIndent, created_at/updated_at kept or added."""
        try:
            parsed = json.loads(settings or "{}")
        except ValueError:
            return settings
        if not isinstance(parsed, dict) or not isinstance(parsed.get("clients"), list) or not parsed["clients"]:
            return settings
        known = {c.get("email"): c for c in clients_of(old)} if old is not None else {}
        for client in parsed["clients"]:
            before = known.get(client.get("email"), {})
            client.setdefault("created_at", before.get("created_at", 1790000000000))
            client.setdefault("updated_at", before.get("updated_at", 1790000000000))
        return json.dumps(parsed, indent=2)

    def _port_taken(self, port, own_id=0):
        return any(i["port"] == port and i["id"] != own_id and i["protocol"] != "amneziawg" for i in self.inbounds)

    def add(self, raw):
        body = bind(raw, INBOUND_FIELDS)
        body.pop("id", None)
        if body.get("protocol") == "amneziawg":
            if any(i["protocol"] == "amneziawg" for i in self.inbounds):
                raise Refusal("awg_exists", "AmneziaWG inbound already exists. Only one is allowed.")
            body["settings"] = '{"clients":[]}'
            body["tag"] = body.get("tag") or "inbound-amneziawg"
            return self._store(body)
        if any(c.get("email", "").lower().startswith(PROBE_PREFIX) for c in clients_of(body.get("settings"))):
            raise Refusal("probe_email", "email is reserved for monitoring probes")
        if self._port_taken(body.get("port", 0)):
            raise Refusal("port_exists", f"Port already exists: {body.get('port')}")
        body["tag"] = f"inbound-{body.get('port', 0)}"
        body["settings"] = self._reserialize(body.get("settings", ""))
        record = self._store(body)
        self._ports_changed()
        return record

    def update(self, inbound_id, raw):
        body = bind(raw, INBOUND_FIELDS)
        old = self.load(inbound_id)
        if self._port_taken(body.get("port", 0), inbound_id):
            raise Refusal("port_exists", f"Port already exists: {body.get('port')}")
        had = {c.get("email") for c in clients_of(old["settings"])}
        for client in clients_of(body.get("settings")):
            if client.get("email", "").lower().startswith(PROBE_PREFIX) and client.get("email") not in had:
                raise Refusal("probe_email", "email is reserved for monitoring probes")
        body["settings"] = self._reserialize(body.get("settings", ""), old["settings"])
        for field in UPDATE_COPIED:
            old[field] = body.get(field, type(old[field])())
        old["tag"] = f"inbound-{old['port']}"
        self._ports_changed()
        return dict(old)

    def set_enable(self, inbound_id, raw):
        body = bind(raw, {"enable": bool})
        inbound = self.load(inbound_id)
        if inbound["enable"] != body.get("enable", False):
            inbound["enable"] = body.get("enable", False)
            self._ports_changed()

    def save_awg(self, raw):
        body = bind(raw, AWG_FIELDS)
        # SaveServer stores what it is given: a body without the keys would wipe them (a re-key in effect).
        if body.get("privateKey") != self.awg["privateKey"] or body.get("publicKey") != self.awg["publicKey"]:
            raise Refusal("awg_keys", "the save would replace the server keys")
        self.awg.update(body)
        for inbound in self.inbounds:
            if inbound["protocol"] == "amneziawg":
                inbound["port"] = self.awg["listenPort"]
        self._ports_changed()

    def new_x25519(self):
        pair = {"privateKey": "x25519-private-" + secrets.token_hex(8), "publicKey": "x25519-public-" + secrets.token_hex(8)}
        self.x25519.append(pair)
        return pair

    def ensure(self):
        """POST /probe/ensure of mon-server: a probe client in every xray inbound, added the way the panel adds a
        client (settings re-serialized)."""
        for inbound in self.inbounds:
            if inbound["protocol"] == "amneziawg":
                continue
            settings = json.loads(inbound["settings"] or "{}")
            email = f"{PROBE_PREFIX}{inbound['id']}"
            if any(c.get("email") == email for c in settings.get("clients") or []):
                continue
            settings.setdefault("clients", []).append({"id": secrets.token_hex(16), "email": email, "enable": True,
                                                        "flow": "", "subId": "probe-sub", "comment": "monitoring probe"})
            inbound["settings"] = self._reserialize(json.dumps(settings), inbound["settings"])

    def state(self):
        return {"inbounds": [dict(i) for i in self.inbounds], "awg": dict(self.awg), "ports": self.ports(),
                "x25519": list(self.x25519)}


ADD_FIELDS = {"name": str, "host": str, "role": str, "subPort": int, "subScheme": str, "position": int}
UPDATE_FIELDS = {"name": str, "host": str, "subPort": int, "subScheme": str, "role": str, "position": int,
                 "state": str, "isActive": bool, "nextHopId": int, "id": int}
DEL_FIELDS = {"force": bool, "skipDrain": bool}


def strict(raw, fields):
    """Decodes a body the way chain_controller.readBody does: empty = zero value, unknown fields refused."""
    if not raw.strip():
        return {}
    try:
        body = json.loads(raw)
    except ValueError as err:
        raise BadRequest(f"chain: invalid body: {err}") from err
    if body is None:  # encoding/json decodes null into a struct as a no-op
        return {}
    if not isinstance(body, dict):
        raise BadRequest("chain: invalid body: not an object")
    for key, value in body.items():
        if key not in fields:
            raise BadRequest(f'chain: invalid body: json: unknown field "{key}"')
        kind = fields[key]
        if value is not None and (not isinstance(value, kind) or (kind is int and isinstance(value, bool))):
            raise BadRequest(f"chain: invalid body: {key} has type {type(value).__name__}")
    return body


class Handler(BaseHTTPRequestHandler):
    registry = None
    install_script = None

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, payload, headers=None, raw=None):
        data = raw if raw is not None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if raw is None else "text/plain")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        return self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        reg = self.registry
        path = self.path.split("?")[0]
        raw = self._body() if method == "POST" else ""
        with reg.lock:
            if path == "/install.sh":
                return self._send(200, None, raw=Path(self.install_script).read_bytes())
            if path == "/test/state":
                return self._send(200, {"hops": reg.ordered(), "revision": reg.revision, "calls": reg.calls,
                                        "issued": reg.issued, "panel": reg.panel.state()})
            if path == "/test/reset":
                reg.reset(json.loads(raw or "[]"))
                return self._send(200, {"ok": True})
            if path == "/test/panel/reset":
                reg.panel.reset(json.loads(raw or "{}"))
                return self._send(200, {"ok": True})
            if path == "/test/panel/ensure":
                reg.panel.ensure()
                return self._send(200, {"ok": True})
            if path == "/test/panel/targets":
                reg.panel.targets = json.loads(raw or "null")
                return self._send(200, {"ok": True})
            if path == "/test/join":
                try:
                    return self._send(200, {"success": True, "obj": reg.join(json.loads(raw)["token"])})
                except Refusal as err:
                    return self._send(404, {"success": False, "msg": str(err)})
            if path == BASE + "login" and method == "POST":
                form = parse_qs(raw)
                ok = form.get("username") == [USER] and form.get("password") == [PASSWORD]
                reg.calls.append({"method": "POST", "path": "login"})
                if not ok:
                    return self._send(200, {"success": False, "msg": "wrong username or password", "obj": None})
                return self._send(200, {"success": True, "msg": "", "obj": None},
                                  headers={"Set-Cookie": COOKIE + "; Path=/base/; HttpOnly"})
            prefix = BASE + "panel/api/"
            if not path.startswith(prefix) or COOKIE not in (self.headers.get("Cookie") or ""):
                return self._send(404, None, raw=b"404 page not found")
            route = path[len(prefix):]
            chain = route.startswith("chain/")
            if chain:
                route = route[len("chain/"):]
            reg.calls.append({"method": method, "path": route, "body": raw})
            try:
                obj = self._route(method, route, raw) if chain else self._panel_route(method, route, raw)
                return self._send(200, {"success": True, "msg": "", "obj": obj})
            except Refusal as err:
                return self._send(200, {"success": False, "msg": f"Refused ({err})", "obj": None})
            except BadRequest as err:
                return self._send(400, {"success": False, "msg": str(err), "obj": None})

    def _route(self, method, route, raw):
        reg = self.registry
        name, _, tail = route.partition("/")
        if method == "GET" and route == "list":
            return reg.listing()
        if method != "POST":
            raise BadRequest(f"no route {method} {route}")
        hop_id = int(tail) if tail.isdigit() else 0
        if name == "add":
            return reg.add(strict(raw, ADD_FIELDS))
        if name == "update":
            return reg.update(hop_id, strict(raw, UPDATE_FIELDS))
        if name == "reissueToken":
            strict(raw, {})
            return reg.reissue(hop_id)
        if name == "setActive":
            strict(raw, {})
            return reg.set_active(hop_id)
        if name == "del":
            return reg.delete(hop_id, strict(raw, DEL_FIELDS))
        raise BadRequest(f"no route {route}")

    def _panel_route(self, method, route, raw):
        panel = self.registry.panel
        tail = route.rsplit("/", 1)[-1]
        inbound_id = int(tail) if tail.isdigit() else 0
        if method == "GET" and route == "inbounds/list":
            return [dict(i) for i in panel.inbounds]
        if method == "GET" and route == "server/getNewX25519Cert":
            return panel.new_x25519()
        if method == "GET" and route == "awg/server":
            return dict(panel.awg)
        if method == "GET" and route == "monitoring/targets":
            if panel.targets is None:
                raise Refusal("monitoring_off", "no targets seeded")
            return panel.targets
        if method != "POST":
            return self._not_found()
        if route == "inbounds/add":
            return panel.add(raw)
        if route.startswith("inbounds/update/"):
            return panel.update(inbound_id, raw)
        if route.startswith("inbounds/setEnable/"):
            return panel.set_enable(inbound_id, raw)
        if route == "awg/server":
            return panel.save_awg(raw)
        return self._not_found()

    @staticmethod
    def _not_found():
        raise BadRequest("404 page not found")


def serve(port, install_script):
    Handler.registry = Registry()
    Handler.install_script = install_script
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
