"""
Intentionally-vulnerable DEMO app for testing TTF end-to-end — stdlib only.

    python examples/demo-app/app.py                    # VULNERABLE (all flaws present)
    TTF_DEMO_FIXED=1 python examples/demo-app/app.py   # FIXED (all flaws closed)

Serves on http://localhost:8777. Local throwaway target for TTF's own scanner/
prober. Do NOT deploy it. Deliberate flaws (each matched by a probe type):
  - IDOR              GET /api/orders/{id}       (no ownership check)
  - function-authz    GET /api/admin/metrics     (no role check)
  - mass-assignment   PATCH /api/users/{id}      (blindly merges body incl. role)
  - auth-bypass       GET /api/internal/health   (no auth required)
  - static-scan bait  hardcoded API key + md5
"""

import json
import os
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer

API_KEY = "sk_live_demo_0123456789abcdef_DO_NOT_SHIP"   # secret-generic bait
def _weak(p):                                            # weak-hash bait
    return hashlib.md5(p.encode()).hexdigest()

FIXED = os.environ.get("TTF_DEMO_FIXED") == "1"

# id 1 = testA (user), id 2 = testB (user), id 9 = admin
USERS = {
    "testA": {"id": 1, "token": "tokenA", "password": "passA", "role": "user", "name": "A"},
    "testB": {"id": 2, "token": "tokenB", "password": "passB", "role": "user", "name": "B"},
    "admin": {"id": 9, "token": "tokenADMIN", "password": "passADMIN", "role": "admin", "name": "Admin"},
}
BY_ID = {u["id"]: u for u in USERS.values()}
TOKENS = {u["token"]: u["id"] for u in USERS.values()}
ORDERS = {
    101: {"id": 101, "owner": 1, "item": "A's widget", "email": "a@example.test", "address": "1 A St"},
    201: {"id": 201, "owner": 2, "item": "B's gadget", "email": "b@example.test", "address": "2 B Ave"},
    202: {"id": 202, "owner": 2, "item": "B's gizmo", "email": "b2@example.test", "address": "2 B Ave"},
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _uid(self):
        h = self.headers.get("Authorization", "")
        token = h[7:] if h.startswith("Bearer ") else h
        return TOKENS.get(token)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    # ---- POST -------------------------------------------------------------- #
    def do_POST(self):
        if self.path == "/api/login":
            d = self._body()
            u = USERS.get(d.get("username"))
            if u and u["password"] == d.get("password"):
                return self._send(200, {"token": u["token"], "user_id": u["id"]})
            return self._send(401, {"error": "bad credentials"})
        self._send(404, {"error": "not found"})

    # ---- PATCH (mass-assignment surface) ----------------------------------- #
    def do_PATCH(self):
        if self.path.startswith("/api/users/"):
            uid = self._uid()
            if uid is None:
                return self._send(401, {"error": "unauthenticated"})
            try:
                target = int(self.path.rsplit("/", 1)[-1])
            except ValueError:
                return self._send(400, {"error": "bad id"})
            user = BY_ID.get(target)
            if not user:
                return self._send(404, {"error": "not found"})
            body = self._body()
            if FIXED:
                # allow-list: only 'name' is writable; role/privileged fields ignored
                if "name" in body:
                    user["name"] = body["name"]
            else:
                # VULN: blindly merge the whole body -> can set role=admin
                user.update(body)
            return self._send(200, {k: user[k] for k in ("id", "name", "role")})
        self._send(404, {"error": "not found"})

    # ---- GET --------------------------------------------------------------- #
    def do_GET(self):
        p = self.path

        # auth-bypass surface: should require auth, but doesn't (unless fixed)
        if p == "/api/internal/health":
            if FIXED and self._uid() is None:
                return self._send(401, {"error": "unauthenticated"})
            return self._send(200, {"db": "connected", "secret_present": bool(API_KEY),
                                    "users": len(USERS)})

        # function-authz surface: admin data, no role check (unless fixed)
        if p == "/api/admin/metrics":
            uid = self._uid()
            if uid is None:
                return self._send(401, {"error": "unauthenticated"})
            if FIXED and BY_ID.get(uid, {}).get("role") != "admin":
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"revenue": 123456, "user_count": len(USERS),
                                    "admin_email": "admin@example.test"})

        # IDOR surface: order by id, no ownership check (unless fixed)
        if p.startswith("/api/orders/"):
            uid = self._uid()
            if uid is None:
                return self._send(401, {"error": "unauthenticated"})
            try:
                oid = int(p.rsplit("/", 1)[-1])
            except ValueError:
                return self._send(400, {"error": "bad id"})
            order = ORDERS.get(oid)
            if not order:
                return self._send(404, {"error": "not found"})
            if FIXED and order["owner"] != uid:
                return self._send(403, {"error": "forbidden"})
            return self._send(200, order)

        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    mode = "FIXED (all flaws closed)" if FIXED else "VULNERABLE (all flaws present)"
    print(f"demo app on http://localhost:8777  [{mode}]")
    HTTPServer(("localhost", 8777), Handler).serve_forever()
