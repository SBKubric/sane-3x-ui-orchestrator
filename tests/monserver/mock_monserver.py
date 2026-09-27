"""Test double of mon-server's admin API (SBKubric/sane-3x-ui-monitoring internal/admin), for role monserver's Settings
step (tasks/settings.yml): POST /admin/login (JSON, mon_session cookie), GET/POST /admin/api/settings (POST replaces the
whole form and needs X-Requested-With) and POST /admin/api/settings/check. Test-only: GET /test/state, POST /test/reset.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER, PASSWORD = "monadmin", "mon-secret"
COOKIE = "mon_session=mock-mon-session"
EMPTY = {"panelUrl": "", "monToken": "", "panelCa": "", "realHost": "", "tgToken": "", "tgChatId": "",
         "pollSeconds": 30}


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset({})

    def reset(self, seed):
        self.settings = dict(EMPTY, **seed)
        self.calls = []


class Handler(BaseHTTPRequestHandler):
    state = None

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, payload, headers=None):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        st = self.state
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode() if method == "POST" else ""
        path = self.path.split("?")[0]
        with st.lock:
            if path == "/test/state":
                return self._send(200, {"settings": st.settings, "calls": st.calls})
            if path == "/test/reset":
                st.reset(json.loads(raw or "{}"))
                return self._send(200, {"ok": True})
            if path == "/admin/login" and method == "POST":
                body = json.loads(raw or "{}")
                if (body.get("username"), body.get("password")) != (USER, PASSWORD):
                    return self._send(401, {"success": False, "msg": "wrong username or password"})
                return self._send(200, {"success": True}, {"Set-Cookie": COOKIE + "; Path=/admin; HttpOnly"})
            if COOKIE not in (self.headers.get("Cookie") or ""):
                return self._send(401, {"success": False, "msg": "login required"})
            if method == "POST" and self.headers.get("X-Requested-With") != "XMLHttpRequest":
                return self._send(403, {"success": False, "msg": "missing X-Requested-With"})
            st.calls.append({"method": method, "path": path, "body": raw})
            if path == "/admin/api/settings" and method == "GET":
                return self._send(200, {"success": True, "obj": {"settings": dict(st.settings)}})
            if path == "/admin/api/settings" and method == "POST":
                body = json.loads(raw or "{}")
                st.settings = {key: body.get(key, type(value)()) for key, value in st.settings.items()}
                return self._send(200, {"success": True, "msg": "Settings saved."})
            if path == "/admin/api/settings/check" and method == "POST":
                return self._send(200, {"success": True, "msg": "Panel reachable.",
                                        "obj": {"revision": 7, "inbounds": 2, "panelVersion": "1.9.0-chain.10"}})
            return self._send(404, {"success": False, "msg": "not found"})


def serve(port):
    Handler.state = State()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
