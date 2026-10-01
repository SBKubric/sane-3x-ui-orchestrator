"""Test double of the 3ax-ui panel API (SBKubric/sane-3x-ui v1.9.0-chain.8), for tests of roles hop and panel:
the chain registry (web/controller/chain_controller.go, web/service/chain_service.go) and, for role panel's
inbounds, the inbound API, the AmneziaWG server and the monitoring page data (see Panel below).

It keeps the parts the role depends on: the login cookie, the {success, msg, obj} envelope with refusals as
HTTP 200 + success false + "<code>: <detail>", strict JSON bodies (unknown fields and wrong types are HTTP 400),
0-based inner positions compacted after every change, next hops re-chained (inner N -> N-1, edges -> last
joined inner), pending/joined/legacy/draining, one-time join tokens, setActive and del refusals, draining of a
hop with live outer neighbours, an edge's neighbour target (realityTarget/realityServerName, validated like
web/service/chain_follow.go neighbourTarget, refused on an inner hop) and the chain-following inbounds that take it
(followChain: rewritten on setActive, on a save while an edge is active, refused without a neighbour target).
Test-only extras: POST /test/join (what `x-ui chain rejoin` does on a box), POST /test/front (a box's front report),
POST /test/chain/update (a registry update by hop name), GET /test/state, POST /test/reset, GET /install.sh (the fake
installer), and for the panel part POST /test/panel/reset, POST /test/panel/ensure, POST /test/panel/targets.

The panel part also has the front's settings (panel/api/nginx/settings|plan|apply|confirm|status, web/service/
nginx_service.go, nginx_apply.go, nginx_confirm.go): apply moves the routed inbounds to the loopback (listen
127.0.0.1, publicPort 443, no PROXY header for Reality) and arms the 2-minute confirmation when it closes ports,
confirm clears it; and the settings form (panel/setting/all|update: update takes the whole form, a key left out
is zeroed). Test hooks: POST /test/panel/nginx (seed settings, blockers, warnings, a pending confirmation).

And the Xray template (web/controller/xray_setting.go, web/service/xray_setting.go): POST panel/xray/ answers the
template in the panel's wrapper (obj = a JSON string {xraySetting, inboundTags, clientReverseTags, outboundTestUrl,
hiddifyCompat}); POST panel/xray/update takes the form (xraySetting, outboundTestUrl: empty = the default URL,
hiddifyCompat: empty = unchanged), refuses JSON that does not parse and pins the api rule first (EnsureStatsRouting);
POST panel/api/server/restartXrayService fails the way xray does on a routing rule whose ext: file is missing from
the asset folder or lacks the category, or on two outbounds with one tag (xray: "existing tag found"). Test hook:
POST /test/panel/xray (template, assetDir, restartFails).

And the panel's WARP (web/service/warp.go, POST panel/xray/warp/<action>): data answers the stored registration (a
JSON string {access_token, device_id, license_key, private_key}, empty when there is none); reg takes the form
privateKey/publicKey, registers with a stand-in of api.cloudflareclient.com and answers {data, config} (config = the
Cloudflare device: id, token, account.license, config.client_id/peers/interface); config answers the device again;
license takes the form license and stores it; del clears the registration. Cloudflare out of reach is a refusal
(success false, "(<error>)"), and an answer without account.license is success with an empty obj, as RegWarp has it.
Test hook: POST /test/panel/warp (data, device, fail: "" | "network" | "empty" | "config", badLicense).

And the domain settings of the form (#224, #225): subPublicURL, vpnName, vpnNameTtl, domainExpiry and dnsExitApiKey,
which panel/setting/all shows only as the mask "********" and a save of the mask keeps. Test hook: POST /test/panel/cli
({flag: value}: what `x-ui setting -vpnName ...` stores, for a fake x-ui). And the front's trusted addresses (#228,
frontTrustedAddrs): the form shows them as stored, `x-ui setting -frontTrustedAddrs` stores them normalised the way
web/entity/front_trusted.go does (comma-separated, masked networks, v4-mapped as v4, order kept, no repeats).
POST /test/panel/reset {"without": [key, ...]} drops form keys (a panel from before a setting).
"""

import base64
import ipaddress
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

# web/service/config.json of the panel: the template of a fresh install.
DEFAULT_XRAY_TEMPLATE = {
    "log": {"access": "none", "dnsLog": False, "error": "", "loglevel": "warning", "maskAddress": ""},
    "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
    "inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 62789, "protocol": "tunnel",
                  "settings": {"address": "127.0.0.1"}}],
    "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs", "redirect": "", "noises": []}},
                  {"tag": "blocked", "protocol": "blackhole", "settings": {}}],
    "policy": {"levels": {"0": {"statsUserDownlink": True, "statsUserUplink": True}},
               "system": {"statsInboundDownlink": True, "statsInboundUplink": True, "statsOutboundDownlink": False,
                          "statsOutboundUplink": False}},
    "routing": {"domainStrategy": "AsIs", "rules": [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
        {"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]},
        {"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]}]},
    "stats": {},
    "metrics": {"tag": "metrics_out", "listen": "127.0.0.1:11111"},
}
DEFAULT_OUTBOUND_TEST_URL = "https://www.google.com/generate_204"

# api.cloudflareclient.com's device (POST/GET /v0a2158/reg), as the panel passes it through.
DEFAULT_WARP_DEVICE = {
    "id": "t.0f5d2c1e-3b1a-4d9e-9c7a-2b8f6e4d1a90", "type": "a", "model": "x-ui", "name": "real",
    "token": "cf-token-3c9d", "warp_enabled": False, "waitlist_enabled": False,
    "account": {"id": "a1b2c3", "account_type": "free", "warp_plus": False, "premium_data": 0, "quota": 0,
                "license": "free-lic-0001"},
    "config": {
        "client_id": "8/+A",
        "peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                   "endpoint": {"v4": "162.159.192.1:0", "v6": "[2606:4700:d0::a29f:c001]:0",
                                "host": "engage.cloudflareclient.com:2408"}}],
        "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a36:df92:102a:9602:fa18"}},
        "services": {"http_proxy": "172.16.0.1:2480"},
    },
}

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


def normalize_front_trusted(raw):
    """entity.NormalizeFrontTrustedAddrs: entries split on , ; space tab CR LF, each an address (v4-mapped as v4, not
    unspecified) or a network (masked, /16 or narrower for IPv4, /32 for IPv6), order kept, no repeats, at most 64."""
    out = []
    for field in raw.replace(";", ",").replace("\t", ",").replace("\r", ",").replace("\n", ",").replace(" ", ",").split(","):
        if not field:
            continue
        if "/" in field:
            net = ipaddress.ip_network(field, strict=False)
            if net.prefixlen < (16 if net.version == 4 else 32):
                raise BadRequest(f"front trusted address {field!r} is too wide a network")
            entry = str(net)
        else:
            if "%" in field:
                raise BadRequest(f"front trusted address {field!r} is neither an IP address nor a network")
            addr = ipaddress.ip_address(field)
            addr = getattr(addr, "ipv4_mapped", None) or addr
            if addr.is_unspecified:
                raise BadRequest(f"front trusted address {field!r} is the unspecified address")
            entry = str(addr)
        if entry not in out:
            out.append(entry)
    if len(out) > 64:
        raise BadRequest(f"at most 64 front trusted addresses, got {len(out)}")
    return ",".join(out)


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
            hop["realityTarget"] = seed.get("realityTarget", "")
            hop["realityServerName"] = seed.get("realityServerName", "")
            hop["frontMode"] = seed.get("frontMode", "off")
            self.hops.append(hop)
        self._reconcile()

    def _new_hop(self, name, host, role, sub_port, sub_scheme):
        hop = {"id": self.next_id, "name": name, "host": host, "role": role, "nextHopId": None, "position": 0,
               "subPort": sub_port, "subScheme": sub_scheme, "state": "pending", "isActive": False,
               "realityTarget": "", "realityServerName": "", "frontMode": "off",
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

    @staticmethod
    def _neighbour(target, server_name):
        """neighbourTarget of the panel: empty = none; host:port with a port 1-65535; an address needs a name."""
        target, server_name = (target or "").strip(), (server_name or "").strip()
        if not target:
            if server_name:
                raise Refusal("invalid_reality_target", f"reality server name {server_name!r} needs a reality target")
            return "", ""
        host, sep, port = target.rpartition(":")
        if not sep or not host or " " in host or "/" in host:
            raise Refusal("invalid_reality_target", f"reality target {target!r} must be host:port")
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise Refusal("invalid_reality_target", f"reality target {target!r} has no port between 1 and 65535")
        if not server_name:
            try:
                ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                return target, ""
            raise Refusal("invalid_reality_server_name",
                          f"reality target {target!r} is an address; give the server name its site answers to")
        try:
            ipaddress.ip_address(server_name)
            is_ip = True
        except ValueError:
            is_ip = False
        if is_ip or any(c in server_name for c in " :/"):
            raise Refusal("invalid_reality_server_name", f"reality server name {server_name!r} must be a domain name")
        return target, server_name

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
        target, server_name = self._neighbour(body.get("realityTarget"), body.get("realityServerName"))
        if target and body["role"] != "edge":
            raise Refusal("reality_target_edge_only", f"{body['name']!r} is an {body['role']} front")
        hop = self._new_hop(body["name"], body["host"].strip(), body["role"], sub_port, sub_scheme)
        hop["realityTarget"], hop["realityServerName"] = target, server_name
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
        if "realityTarget" in body or "realityServerName" in body:
            # Update: an omitted field keeps its value; an empty realityTarget clears the server name too.
            target = body.get("realityTarget", hop["realityTarget"])
            server_name = body.get("realityServerName", hop["realityServerName"]) if target else ""
            target, server_name = self._neighbour(target, server_name)
            if target and hop["role"] != "edge":
                raise Refusal("reality_target_edge_only", f"{hop['name']!r} is an {hop['role']} front")
            if (target, server_name) != (hop["realityTarget"], hop["realityServerName"]):
                if hop["isActive"]:
                    self.panel.follow_edge(dict(hop, realityTarget=target, realityServerName=server_name))
                hop["realityTarget"], hop["realityServerName"], changed = target, server_name, True
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
        self.panel.follow_edge(hop)
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

    def join(self, token, reported=None):
        hop_id = self.tokens.pop(token, None)
        if hop_id is None:
            raise Refusal("unknown_token", "unknown, expired or spent")
        hop = self.load(hop_id)
        hop["state"], hop["joinTokenExpires"] = "joined", 0
        # applyReportedAddress: what the box reports about itself wins over what was typed.
        for field in ("host", "subPort", "subScheme"):
            if (reported or {}).get(field):
                hop[field] = reported[field]
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
                  "sniffing": str, "publicPort": int, "followChain": bool}
UPDATE_COPIED = ("up", "down", "total", "remark", "enable", "expiryTime", "trafficReset", "listen", "port", "protocol",
                 "settings", "streamSettings", "sniffing", "followChain")
AWG_FIELDS = {"kind": str, "id": int, "enable": bool, "interfaceName": str, "listenPort": int, "mtu": int,
              "privateKey": str, "publicKey": str, "jc": int, "jmin": int, "jmax": int, "s1": int, "s2": int, "s3": int,
              "s4": int, "h1": str, "h2": str, "h3": str, "h4": str, "i1": str, "i2": str, "i3": str, "i4": str, "i5": str,
              "endpoint": str, "routeViaXray": bool, "xrayInboundTag": str, "xrayTproxyPort": int,
              # AmneziaWG 3.0 (model.TunnelServer): header protection, the one-sided ranges, two switches.
              "headerProtectionKey": str, "contentPaddingAddition": str, "rekeyAfterTime": str, "rekeyTimeout": str,
              "rejectAfterTime": str, "keepaliveTimeout": str, "maxHandshakeAttempts": str, "randomTrailers": bool,
              "disableCookies": bool}
# The 3.0 range fields, in the order tunnel.writeObfuscation30 writes them, with their config names.
AWG_V3_RANGES = [("contentPaddingAddition", "ContentPaddingAddition"), ("rekeyAfterTime", "RekeyAfterTime"),
                 ("rekeyTimeout", "RekeyTimeout"), ("rejectAfterTime", "RejectAfterTime"),
                 ("keepaliveTimeout", "KeepaliveTimeout"), ("maxHandshakeAttempts", "MaxHandshakeAttempts")]


def hp_key():
    """A header protection key as tunnel.GenerateHeaderProtectionKey makes it: base64 of 32 random bytes."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def validate_awg(server):
    """tunnel.ValidateObfuscation, the parts the role can trip: S3/S4 bounds, the 3.0 ranges, the key, and
    header protection's S1-S4 >= 12."""
    if not 0 <= server["s3"] <= 64 or not 0 <= server["s4"] <= 32:
        raise Refusal("awg_obf", f"invalid S3/S4 {server['s3']}/{server['s4']}")
    for field, name in AWG_V3_RANGES:
        value = (server.get(field) or "").strip()
        if not value:
            continue
        low, _, high = value.partition("-")
        try:
            low, high = int(low), int(high or low)
        except ValueError as err:
            raise Refusal("awg_obf", f"invalid {name}: {value!r}") from err
        if low < 0 or high > 65535 or low > high:
            raise Refusal("awg_obf", f"invalid {name}: {value!r}")
    key = (server.get("headerProtectionKey") or "").strip()
    if not key:
        return
    try:
        raw = base64.b64decode(key, validate=True)
    except ValueError as err:
        raise Refusal("awg_obf", "invalid HeaderProtectionKey: must be base64") from err
    if len(raw) != 32:
        raise Refusal("awg_obf", f"invalid HeaderProtectionKey: must decode to 32 bytes, got {len(raw)}")
    for i, pad in enumerate([server["s1"], server["s2"], server["s3"], server["s4"]], 1):
        if pad < 12:
            raise Refusal("awg_obf", f"padding S{i} = {pad} is too small for header protection")


def awg_obfuscation_lines(server, v3):
    """tunnel.writeObfuscation: the 2.0 set, then the 3.0 one only where the kernel takes it (SupportsV3)."""
    lines = [f"Jc = {server['jc']}", f"Jmin = {server['jmin']}", f"Jmax = {server['jmax']}", f"S1 = {server['s1']}",
             f"S2 = {server['s2']}"]
    lines += [f"S{i} = {server[f's{i}']}" for i in (3, 4) if server[f"s{i}"] > 0]
    lines += [f"H{i} = {server[f'h{i}'] or i}" for i in range(1, 5)]
    lines += [f"I{i} = {server[f'i{i}']}" for i in range(1, 6) if server[f"i{i}"]]
    if v3:
        if (server.get("headerProtectionKey") or "").strip():
            lines.append(f"HeaderProtectionKey = {server['headerProtectionKey'].strip()}")
        lines += [f"{name} = {server[field].strip()}" for field, name in AWG_V3_RANGES if (server.get(field) or "").strip()]
        lines += [f"{name} = on" for field, name in (("randomTrailers", "RandomTrailers"), ("disableCookies", "DisableCookies"))
                  if server.get(field)]
    return lines


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

    NGINX_DEFAULTS = {"mode": "shared", "domain": "", "stubSiteId": 0, "subsBehind443": False, "panelBehind443": False,
                      "manageFirewall": False, "firewallExtra": "", "realityPort": 8443, "httpPort": 0}
    SETTINGS_DEFAULTS = {"webListen": "", "webDomain": "", "webPort": 2053, "webCertFile": "/etc/x-ui/tls/panel.crt",
                         "webKeyFile": "/etc/x-ui/tls/panel.key", "webBasePath": "/base/", "sessionMaxAge": 360,
                         "tgBotEnable": False, "tgBotToken": "", "tgBotChatId": "", "subEnable": True, "subPort": 2096,
                         "subPath": "/sub/", "subJsonEnable": True, "subJsonPath": "/json/", "chainPanelHost": "",
                         "timeLocation": "Local", "externalTrafficInformEnable": False,
                         "subPublicURL": "", "dnsExitApiKey": "", "vpnName": "", "vpnNameTtl": 5, "domainExpiry": "",
                         "frontTrustedAddrs": "", "tgNotifyChatId": ""}
    # entity.DnsExitApiKeyMask: what the form and the API show for a stored DNSExit API key.
    KEY_MASK = "********"

    def reset(self, seed):
        self.nginx = dict(self.NGINX_DEFAULTS, **seed.get("nginx", {}))
        self.nginx_blockers = []
        self.nginx_warnings = []
        self.confirm_deadline = 0
        self.settings = dict(self.SETTINGS_DEFAULTS, **seed.get("settings", {}))
        for key in seed.get("without", []):
            self.settings.pop(key, None)
        self.inbounds = []
        self.next_id = 1
        self.x25519 = list(seed.get("x25519", []))
        self.x25519_next = list(seed.get("x25519Next", []))
        self.targets = seed.get("targets")
        self.xray_template = json.dumps(seed.get("xrayTemplate", DEFAULT_XRAY_TEMPLATE))
        self.outbound_test_url = DEFAULT_OUTBOUND_TEST_URL
        self.hiddify_compat = False
        self.xray_asset_dir = seed.get("xrayAssetDir")
        self.xray_restart_fails = False
        self.xray_restarts = 0
        self.xray_need_restart = False
        self.awg_bounces = 0
        self.warp = seed.get("warp", "")
        self.warp_device = json.loads(json.dumps(seed.get("warpDevice", DEFAULT_WARP_DEVICE)))
        self.warp_fail = ""
        self.warp_bad_license = ""
        self.awg = {"kind": "awg", "id": 1, "enable": False, "interfaceName": "awg0", "listenPort": 38810, "mtu": 1420,
                    "privateKey": "awg-private-" + secrets.token_hex(8), "publicKey": "awg-public", "jc": 5,
                    "jmin": 49, "jmax": 180, "s1": 40, "s2": 120, "s3": 20, "s4": 16,
                    "h1": "1-100", "h2": "200-300", "h3": "400-500", "h4": "600-700",
                    # What the panel seeds a new server with (tunnel.GenerateObfuscation20): random I1, I2-I5 its own.
                    "i1": "<r 153>", "i2": "<b 0xc30000000108><r 20>", "i3": "<b 0x000100002112a442><r 16>",
                    "i4": "<b 0x16feff00000000000000><r 30>", "i5": "<t><r 40>", "endpoint": "10.0.0.1",
                    "routeViaXray": False, "xrayInboundTag": "awg-tproxy-in", "xrayTproxyPort": 12345,
                    # A host whose kernel module takes 3.0 (supportsV3) seeds the 3.0 set on top
                    # (tunnel.GenerateObfuscation30): a fresh key and random ranges around WireGuard's timers.
                    "headerProtectionKey": hp_key(), "contentPaddingAddition": "5-41", "rekeyAfterTime": "103-121",
                    "rekeyTimeout": "5-7", "rejectAfterTime": "171-190", "keepaliveTimeout": "9-13",
                    "maxHandshakeAttempts": "15-20", "randomTrailers": True, "disableCookies": False}
        self.awg.update(seed.get("awg", {}))
        # tunnel.SupportsV3: whether the host's kernel module takes the 3.0 parameters (awg/server/status).
        self.awg_supports_v3 = seed.get("supportsV3", True)
        # Where the panel writes <interfaceName>.conf when it applies the server (the test's temp dir, or none).
        self.awg_conf_dir = seed.get("awgConfDir")
        self.awg_generated = []
        self._write_awg_conf()
        # AWG peers (GET awg/clients): users and the monitoring probe peers alike.
        self.awg_clients = list(seed.get("awgClients", []))
        for inbound in seed.get("inbounds", []):
            self._store(dict(inbound))

    def _store(self, inbound):
        record = {"id": self.next_id, "up": 0, "down": 0, "total": 0, "allTime": 0, "remark": "", "enable": True,
                  "expiryTime": 0, "trafficReset": "never", "lastTrafficResetTime": 0, "clientStats": [],
                  "listen": "", "port": 0, "protocol": "", "settings": "", "streamSettings": "", "tag": "",
                  "sniffing": "", "publicPort": 0, "followChain": False}
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

    @staticmethod
    def _neighbour_stream(stream_settings, edge):
        """withNeighbourTarget: target and strict serverNames of the edge's neighbour, a legacy dest dropped."""
        stream = json.loads(stream_settings or "{}")
        if stream.get("security") != "reality":
            raise Refusal("follow_chain_not_reality", f"security is {stream.get('security')!r}, not reality")
        name = edge["realityServerName"] or edge["realityTarget"].rpartition(":")[0]
        reality = stream.setdefault("realitySettings", {})
        reality["target"] = edge["realityTarget"]
        reality.pop("dest", None)
        reality["serverNames"] = [name]
        if isinstance(reality.get("settings"), dict):
            reality["settings"]["serverName"] = name
        return json.dumps(stream, indent=2)

    def _active_edge(self):
        return next((h for h in self.registry.hops if h["isActive"]), None)

    def prepare_follower(self, body):
        """PrepareFollower: a flagged inbound must be Reality and takes the active edge's neighbour on every save."""
        if not body.get("followChain"):
            return
        if json.loads(body.get("streamSettings") or "{}").get("security") != "reality":
            raise Refusal("follow_chain_not_reality", f"inbound {body.get('remark')!r} cannot follow the chain")
        edge = self._active_edge()
        if edge is None:
            return
        if not edge["realityTarget"]:
            raise Refusal("no_neighbour_target", f"the active edge {edge['name']!r} has no neighbour target")
        body["streamSettings"] = self._neighbour_stream(body.get("streamSettings"), edge)

    def follow_edge(self, edge):
        """followEdgeTx: every flagged inbound takes the edge's neighbour; refused without one."""
        followers = [i for i in self.inbounds if i.get("followChain")]
        if followers and not edge["realityTarget"]:
            raise Refusal("no_neighbour_target", f"{edge['name']!r} has no neighbour target")
        for inbound in followers:
            inbound["streamSettings"] = self._neighbour_stream(inbound["streamSettings"], edge)

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
        self.prepare_follower(body)
        body["tag"] = f"inbound-{body.get('port', 0)}"
        body["settings"] = self._reserialize(body.get("settings", ""))
        record = self._store(body)
        self._ports_changed()
        return record

    def update(self, inbound_id, raw):
        body = bind(raw, INBOUND_FIELDS)
        self.prepare_follower(body)
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
        # SaveServer: a new routeViaXray (or its tag/port) bounces the interface and asks for an xray restart, which the
        # panel's 30 s job does unless someone restarts xray first.
        if any(body.get(k, self.awg[k]) != self.awg[k] for k in ("routeViaXray", "xrayInboundTag", "xrayTproxyPort")):
            self.awg_bounces += 1
            self.xray_need_restart = True
        validate_awg(dict(self.awg, **body))
        self.awg.update(body)
        for inbound in self.inbounds:
            if inbound["protocol"] == "amneziawg":
                inbound["port"] = self.awg["listenPort"]
        self._ports_changed()
        self._write_awg_conf()

    def _write_awg_conf(self):
        """WriteServerConfig: the server's [Interface] as tunnel.GenerateServerConfig writes it (no peers here)."""
        if not self.awg_conf_dir:
            return
        server = self.awg
        lines = ["[Interface]", f"PrivateKey = {server['privateKey']}", "Address = 198.51.100.1/24",
                 f"ListenPort = {server['listenPort']}", f"MTU = {server['mtu']}"]
        lines += awg_obfuscation_lines(server, self.awg_supports_v3)
        Path(self.awg_conf_dir, (server["interfaceName"] or "awg0") + ".conf").write_text("\n".join(lines) + "\n")

    def awg_status(self):
        return {"running": self.awg["enable"], "awgInstalled": True, "awgVersion": "v3.1.20260812",
                "supportsV3": self.awg_supports_v3}

    def awg_generate(self, query):
        """POST awg/server/generate: a fresh parameter set, saved nowhere; std=3 adds the 3.0 half (a new key)."""
        out = {"jc": 4, "jmin": 50, "jmax": 120, "s1": 30, "s2": 60, "s3": 20, "s4": 14, "h1": "5-2000",
               "h2": "600000000-600002000", "h3": "1100000000-1100002000", "h4": "1700000000-1700002000",
               "i1": "<r 64>", "i2": "", "i3": "", "i4": "", "i5": ""}
        if query.get("std") == ["3"]:
            if not self.awg_supports_v3:
                raise Refusal("generate", "AmneziaWG 3.0 needs newer amneziawg-tools and kernel module on this server")
            key = hp_key()
            self.awg_generated.append(key)
            out.update({"headerProtectionKey": key, "contentPaddingAddition": "3-30", "rekeyAfterTime": "100-120",
                        "rekeyTimeout": "4-6", "rejectAfterTime": "170-190", "keepaliveTimeout": "8-11",
                        "maxHandshakeAttempts": "14-18", "randomTrailers": True, "disableCookies": False})
        return out

    def awg_client_config(self, client_id):
        """GET awg/client/<id>/config: tunnel.GenerateClientConfig, the server's obfuscation in [Interface]."""
        client = next((c for c in self.awg_clients if c.get("id") == client_id), None)
        if client is None:
            raise Refusal("get client config", "record not found")
        if "config" in client:  # a test's stand-in for a .conf that no longer follows the server
            return client["config"]
        lines = ["[Interface]", f"PrivateKey = client-private-{client_id}", f"Address = 198.51.100.{client_id + 1}/32",
                 "DNS = 192.0.2.53", f"MTU = {self.awg['mtu']}"]
        lines += awg_obfuscation_lines(self.awg, self.awg_supports_v3)
        lines += ["", "[Peer]", f"PublicKey = {self.awg['publicKey']}", f"Endpoint = {self.awg['endpoint']}:{self.awg['listenPort']}",
                  "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25"]
        return "\n".join(lines) + "\n"

    def new_x25519(self):
        # xray x25519 prints base64url without padding; x25519Next seeds the next pairs.
        pair = self.x25519_next.pop(0) if self.x25519_next else {"privateKey": "x25519-private-" + secrets.token_hex(8),
                                                                  "publicKey": "x25519-public-" + secrets.token_hex(8)}
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

    # --- the front (nginx) -----------------------------------------------------------------------------
    def _routes(self):
        """collectRoutes: enabled VLESS Reality inbounds are what the front can route by server name."""
        return [i for i in self.inbounds if i["enable"] and i["protocol"] == "vless"
                and json.loads(i["streamSettings"] or "{}").get("security") == "reality"]

    @staticmethod
    def _closes_ports(nginx):
        return nginx["mode"] == "only443" and nginx["manageFirewall"]

    @staticmethod
    def _normalized(nginx):
        """GetSettings: off drops every switch, shared drops the panel and the firewall."""
        out = dict(nginx)
        if out["mode"] in ("off", ""):
            out.update(subsBehind443=False, panelBehind443=False, manageFirewall=False)
        elif out["mode"] == "shared":
            out.update(panelBehind443=False, manageFirewall=False)
        return out

    def nginx_settings(self):
        return self._normalized(self.nginx)

    def nginx_plan(self, raw):
        body = bind(raw, {"mode": str, "domain": str, "stubSiteId": int, "subsBehind443": bool, "panelBehind443": bool,
                          "manageFirewall": bool, "firewallExtra": str, "realityPort": int, "httpPort": int})
        blockers = list(self.nginx_blockers)
        if body.get("mode") != "off" and not self._routes():
            blockers.append({"code": "nothingToRoute"})
        return {"mode": body.get("mode", ""), "changes": [], "blockers": blockers, "warnings": list(self.nginx_warnings)}

    def nginx_apply(self, raw):
        body = bind(raw, {"mode": str, "domain": str, "stubSiteId": int, "subsBehind443": bool, "panelBehind443": bool,
                          "manageFirewall": bool, "firewallExtra": str, "realityPort": int, "httpPort": int})
        if body.get("mode") not in ("off", "shared", "only443"):
            raise Refusal("invalid_request", f"unknown mode {body.get('mode')!r}")
        previous = self.nginx_settings()
        wanted = self._normalized(dict(self.NGINX_DEFAULTS, **body))
        if wanted["mode"] != "off":
            if not self._routes():
                raise Refusal("nothing_to_route", "no inbound can be routed by server name")
            for inbound in self._routes():
                stream = json.loads(inbound["streamSettings"])
                stream.setdefault("sockopt", {})["acceptProxyProtocol"] = False
                inbound.update(listen="127.0.0.1", publicPort=443, streamSettings=json.dumps(stream, indent=2))
        self.nginx = wanted
        if self._closes_ports(wanted) and (not self._closes_ports(previous)
                                           or (wanted["panelBehind443"] and not previous["panelBehind443"])):
            self.confirm_deadline = 1790000120000

    def nginx_confirm(self):
        self.confirm_deadline = 0

    def nginx_status(self):
        nginx = self.nginx_settings()
        return {"installed": True, "running": True, "mode": nginx["mode"], "domain": nginx["domain"],
                "firewallOn": self._closes_ports(nginx), "confirmDeadline": self.confirm_deadline,
                "ipCertFile": "/root/cert/ip/fullchain.pem", "publicPort": 443, "routes": [],
                "warnings": list(self.nginx_warnings)}

    # --- the settings form ------------------------------------------------------------------------------
    def form_settings(self):
        """GetAllSetting: the DNSExit API key only as the mask (or empty when none is stored)."""
        form = dict(self.settings)
        if form["dnsExitApiKey"]:
            form["dnsExitApiKey"] = self.KEY_MASK
        return form

    def update_settings(self, raw):
        body = json.loads(raw or "{}")
        # UpdateAllSetting saves every field of the form: one left out goes back to its zero value; the key's mask
        # keeps the stored key, a vpnNameTtl of 0 (a form from before the setting) becomes the default 5.
        if body.get("dnsExitApiKey") == self.KEY_MASK:
            body["dnsExitApiKey"] = self.settings["dnsExitApiKey"]
        settings = {key: body.get(key, type(value)()) for key, value in self.settings.items()}
        settings["vpnNameTtl"] = settings["vpnNameTtl"] or 5
        self.settings = settings

    def cli_settings(self, values):
        """What `x-ui setting -dnsExitApiKey/-vpnName/-vpnNameTtl/-domainExpiry` stores (the fake x-ui of the tests)."""
        for key, value in values.items():
            if key not in ("dnsExitApiKey", "vpnName", "vpnNameTtl", "domainExpiry", "frontTrustedAddrs") or key not in self.settings:
                raise BadRequest(f"no such flag -{key}")
            if key == "vpnNameTtl":
                self.settings[key] = int(value)
            elif key == "vpnName":
                self.settings[key] = value.strip().lower().rstrip(".")
            elif key == "frontTrustedAddrs":
                self.settings[key] = normalize_front_trusted(value)
            else:
                self.settings[key] = value.strip()

    # --- the Xray template ----------------------------------------------------------------------------------
    def xray_setting(self):
        return json.dumps({"xraySetting": json.loads(self.xray_template), "inboundTags": "[]", "clientReverseTags": "[]",
                           "outboundTestUrl": self.outbound_test_url, "hiddifyCompat": self.hiddify_compat})

    def xray_update(self, raw):
        form = parse_qs(raw, keep_blank_values=True)
        template = form.get("xraySetting", [""])[0]
        try:
            config = json.loads(template)
        except ValueError as err:
            raise Refusal("xray", f"xray template config invalid: {err}") from err
        rules = config.get("routing", {}).get("rules", [])
        api = [i for i, r in enumerate(rules) if r.get("outboundTag") == "api" and "api" in (r.get("inboundTag") or [])]
        if not api or api[0] != 0:  # EnsureStatsRouting: re-marshalled only when it moves the api rule
            rule = rules.pop(api[0]) if api else {"type": "field", "inboundTag": ["api"], "outboundTag": "api"}
            config.setdefault("routing", {})["rules"] = [rule] + rules
            template = json.dumps(config, sort_keys=True)
        self.xray_template = template
        self.outbound_test_url = form.get("outboundTestUrl", [""])[0] or DEFAULT_OUTBOUND_TEST_URL
        if form.get("hiddifyCompat", [""])[0]:
            self.hiddify_compat = form["hiddifyCompat"][0] == "true"

    def xray_restart(self):
        self.xray_restarts += 1
        self.xray_need_restart = False
        if self.xray_restart_fails:
            raise Refusal("xray", "Failed to restart xray-core")
        tags = [o.get("tag") for o in json.loads(self.xray_template).get("outbounds", []) if o.get("tag")]
        for tag in tags:
            if tags.count(tag) > 1:
                raise Refusal("xray", f"failed to add outbound handler > existing tag found: {tag}")
        for rule in json.loads(self.xray_template).get("routing", {}).get("rules", []):
            for entry in rule.get("domain", []):
                if not entry.startswith("ext:"):
                    continue
                _, name, category = entry.split(":", 2)
                path = os.path.join(self.xray_asset_dir or "/nonexistent", name)
                if not os.path.isfile(path):
                    raise Refusal("xray", f"failed to load file: {name} > open {path}: no such file or directory")
                with open(path, "rb") as f:
                    if category.upper().encode() not in f.read().upper():
                        raise Refusal("xray", f"list not found in {name}: {category}")

    # --- WARP -------------------------------------------------------------------------------------------------
    def _cloudflare(self, url):
        if self.warp_fail == "network":
            raise Refusal("warp", f'Post "{url}": dial tcp 162.159.192.1:443: i/o timeout')

    def warp_action(self, action, raw):
        """The obj of POST panel/xray/warp/<action> (a string, as the panel answers it)."""
        form = parse_qs(raw, keep_blank_values=True)
        if action == "data":
            return self.warp
        if action == "del":
            self.warp = ""
            return ""
        if action == "reg":
            self._cloudflare("https://api.cloudflareclient.com/v0a2158/reg")
            if self.warp_fail == "empty":
                return ""  # RegWarp: no account.license in the answer -> "", nil
            data = {"access_token": self.warp_device["token"], "device_id": self.warp_device["id"],
                    "license_key": self.warp_device["account"]["license"],
                    "private_key": form.get("privateKey", [""])[0]}
            self.warp_device["key"] = form.get("publicKey", [""])[0]
            self.warp = json.dumps(data, indent=2)
            return json.dumps({"data": data, "config": self.warp_device}, indent=2)
        data = json.loads(self.warp)  # config and license on an empty registration: json.Unmarshal fails
        if action == "config":
            self._cloudflare(f"https://api.cloudflareclient.com/v0a2158/reg/{data['device_id']}")
            if self.warp_fail == "config":
                return json.dumps({"success": False, "errors": [{"code": 1000, "message": "Unauthorized"}]})
            return json.dumps(self.warp_device)
        if action == "license":
            self._cloudflare(f"https://api.cloudflareclient.com/v0a2158/reg/{data['device_id']}/account")
            license_key = form.get("license", [""])[0]
            if license_key == self.warp_bad_license:
                raise Refusal("warp", "[100 Invalid license]")
            data["license_key"] = license_key
            self.warp = json.dumps(data, indent=2)
            return self.warp
        return ""

    def state(self):
        return {"inbounds": [dict(i) for i in self.inbounds], "awg": dict(self.awg), "ports": self.ports(),
                "x25519": list(self.x25519), "nginx": dict(self.nginx), "confirmDeadline": self.confirm_deadline,
                "settings": dict(self.settings), "xrayTemplate": json.loads(self.xray_template),
                "outboundTestUrl": self.outbound_test_url, "hiddifyCompat": self.hiddify_compat,
                "xrayRestarts": self.xray_restarts, "warp": self.warp, "warpDevice": self.warp_device,
                "xrayNeedRestart": self.xray_need_restart, "awgBounces": self.awg_bounces,
                "awgGenerated": list(self.awg_generated)}


ADD_FIELDS = {"name": str, "host": str, "role": str, "subPort": int, "subScheme": str, "position": int,
              "realityTarget": str, "realityServerName": str}
UPDATE_FIELDS = {"name": str, "host": str, "subPort": int, "subScheme": str, "role": str, "position": int,
                 "state": str, "isActive": bool, "nextHopId": int, "id": int, "realityTarget": str,
                 "realityServerName": str}
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
            if path == "/test/panel/nginx":
                seed = json.loads(raw or "{}")
                reg.panel.nginx.update(seed.get("settings", {}))
                reg.panel.nginx_blockers = seed.get("blockers", [])
                reg.panel.nginx_warnings = seed.get("warnings", [])
                reg.panel.confirm_deadline = seed.get("confirmDeadline", reg.panel.confirm_deadline)
                return self._send(200, {"ok": True})
            if path == "/test/panel/xray":
                seed = json.loads(raw or "{}")
                if "template" in seed:
                    reg.panel.xray_template = json.dumps(seed["template"])
                reg.panel.xray_asset_dir = seed.get("assetDir", reg.panel.xray_asset_dir)
                reg.panel.xray_restart_fails = seed.get("restartFails", reg.panel.xray_restart_fails)
                reg.panel.outbound_test_url = seed.get("outboundTestUrl", reg.panel.outbound_test_url)
                reg.panel.hiddify_compat = seed.get("hiddifyCompat", reg.panel.hiddify_compat)
                return self._send(200, {"ok": True})
            if path == "/test/panel/warp":
                seed = json.loads(raw or "{}")
                if "data" in seed:
                    reg.panel.warp = json.dumps(seed["data"], indent=2) if seed["data"] else ""
                if "device" in seed:
                    reg.panel.warp_device = seed["device"]
                reg.panel.warp_fail = seed.get("fail", reg.panel.warp_fail)
                reg.panel.warp_bad_license = seed.get("badLicense", reg.panel.warp_bad_license)
                return self._send(200, {"ok": True})
            if path == "/test/panel/cli":
                reg.panel.cli_settings(json.loads(raw or "{}"))
                return self._send(200, {"ok": True})
            if path == "/test/panel/targets":
                reg.panel.targets = json.loads(raw or "null")
                return self._send(200, {"ok": True})
            if path == "/test/chain/update":
                body = json.loads(raw)
                hop = next(h for h in reg.hops if h["name"] == body.pop("name"))
                reg.update(hop["id"], body)
                return self._send(200, {"ok": True})
            if path == "/test/front":
                # RecordFront: the box's report moves its sub port and scheme, and the revision with them.
                body = json.loads(raw)
                hop = next(h for h in reg.hops if h["name"] == body["name"])
                hop["frontMode"] = body["mode"]
                if (hop["subPort"], hop["subScheme"]) != (body["subPort"], body["subScheme"]):
                    hop["subPort"], hop["subScheme"] = body["subPort"], body["subScheme"]
                    reg.revision += 1
                return self._send(200, {"ok": True})
            if path == "/test/join":
                body = json.loads(raw)
                try:
                    return self._send(200, {"success": True, "obj": reg.join(body["token"], reported=body)})
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
            if path.startswith(BASE + "panel/setting/") and COOKIE in (self.headers.get("Cookie") or ""):
                route = path[len(BASE + "panel/setting/"):]
                reg.calls.append({"method": method, "path": "setting/" + route, "body": raw})
                if method == "POST" and route == "all":
                    return self._send(200, {"success": True, "msg": "", "obj": reg.panel.form_settings()})
                if method == "POST" and route == "update":
                    reg.panel.update_settings(raw)
                    return self._send(200, {"success": True, "msg": "", "obj": None})
                return self._send(404, None, raw=b"404 page not found")
            if path.startswith(BASE + "panel/xray/") and COOKIE in (self.headers.get("Cookie") or ""):
                route = path[len(BASE + "panel/xray/"):]
                reg.calls.append({"method": method, "path": "xray/" + route, "body": raw})
                try:
                    if method == "POST" and route == "":
                        return self._send(200, {"success": True, "msg": "", "obj": reg.panel.xray_setting()})
                    if method == "POST" and route == "update":
                        reg.panel.xray_update(raw)
                        return self._send(200, {"success": True, "msg": "Settings modified", "obj": None})
                    if method == "POST" and route.startswith("warp/"):
                        return self._send(200, {"success": True, "msg": "",
                                                "obj": reg.panel.warp_action(route[len("warp/"):], raw)})
                except Refusal as err:
                    return self._send(200, {"success": False, "msg": str(err), "obj": None})
                except ValueError as err:  # json.Unmarshal of an empty registration
                    return self._send(200, {"success": False, "msg": f" ({err})", "obj": ""})
                return self._send(404, None, raw=b"404 page not found")
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
        if method == "GET" and route == "awg/clients":
            return [dict(c) for c in panel.awg_clients]
        if method == "GET" and route == "awg/server/status":
            return panel.awg_status()
        if method == "GET" and route.startswith("awg/client/") and route.endswith("/config") and route.split("/")[2].isdigit():
            return panel.awg_client_config(int(route.split("/")[2]))
        if method == "GET" and route == "nginx/settings":
            return panel.nginx_settings()
        if method == "GET" and route == "nginx/status":
            return panel.nginx_status()
        if method == "POST" and route == "nginx/plan":
            return panel.nginx_plan(raw)
        if method == "POST" and route == "nginx/apply":
            return panel.nginx_apply(raw)
        if method == "POST" and route == "nginx/confirm":
            return panel.nginx_confirm()
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
        if route == "awg/server/generate":
            return panel.awg_generate(parse_qs(self.path.partition("?")[2]))
        if route == "server/restartXrayService":
            return panel.xray_restart()
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
