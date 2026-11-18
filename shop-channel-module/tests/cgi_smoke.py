"""Exercise request parsing, HTTP status, headers and persistence without a socket."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
cgi = shutil.which("php-cgi")
if not cgi:
    raise SystemExit("php-cgi is required for this smoke test")
with tempfile.TemporaryDirectory(prefix="shop-test-") as tmp:
    base = dict(os.environ, REDIRECT_STATUS="200", GATEWAY_INTERFACE="CGI/1.1",
                SERVER_PROTOCOL="HTTP/1.1", SERVER_NAME="localhost", SERVER_PORT="80",
                REMOTE_ADDR="127.0.0.1", SCRIPT_FILENAME=str(root / "public/index.php"),
                SCRIPT_NAME="/index.php", SHOP_DB=str(Path(tmp) / "test.sqlite"),
                SHOP_ADMIN_TOKEN="a" * 48, SHOP_INTEGRATION_TOKEN="i" * 48)

    def request(method, path, data=None, role=None, extra=None):
        body = b"" if data is None else json.dumps(data).encode()
        env = dict(base, REQUEST_METHOD=method, REQUEST_URI=path,
                   QUERY_STRING=path.partition("?")[2], CONTENT_TYPE="application/json",
                   CONTENT_LENGTH=str(len(body)))
        env.pop("HTTP_AUTHORIZATION", None)
        if role:
            env["HTTP_AUTHORIZATION"] = "Bearer " + base["SHOP_" + role + "_TOKEN"]
        env.update(extra or {})
        result = subprocess.run([cgi], env=env, input=body, capture_output=True, timeout=5, check=True)
        head, _, payload = result.stdout.replace(b"\r\n", b"\n").partition(b"\n\n")
        headers = {k.strip().lower(): v.strip() for k, v in
                   (line.decode().split(":", 1) for line in head.splitlines())}
        return int(headers.get("status", "200").split()[0]), headers, payload

    assert request("PUT", "/admin/channels/bindings", {"site":"br","project":"winter"})[0] == 401
    for project in ["winter", "studio"]:
        assert request("PUT", "/admin/channels/bindings", {"site":"br","project":project}, "ADMIN")[0] == 200
    link = {"site":"br","project":"winter","channel":"email","destination":"/products/coffee","active":True}
    assert request("PUT", "/admin/channels/links", {**link,"destination":"//other.test"}, "ADMIN")[0] == 400
    assert request("PUT", "/admin/channels/links", link, "ADMIN")[0] == 200
    for extra in [{}, {"REMOTE_ADDR":"203.0.113.1","HTTP_USER_AGENT":"test crawler",
                       "HTTP_CF_CONNECTING_IP":"192.0.2.1","HTTP_ACCEPT_LANGUAGE":"pt-BR"}]:
        status, headers, _ = request("GET", "/go/br/winter/email?url=https://other.test", extra=extra)
        assert status == 302 and headers["location"] == "/products/coffee"
        assert "no-store" in headers["cache-control"]
    assert request("GET", "/go/br/studio/email")[0] == 404
    assert request("GET", "/")[2] == request("GET", "/", extra={"REMOTE_ADDR":"203.0.113.1","HTTP_USER_AGENT":"test crawler"})[2]
    assert request("GET", "/admin/channels/links?site=br", role="ADMIN")[0] == 200

    import time
    deny = {"cidr":"192.0.2.0/24","scope":"login","expires_at":int(time.time())+3600,"note":"smoke"}
    path = "/admin/operation-denies"
    assert request("POST", path, {"entries":[deny]}, "ADMIN")[0] == 200
    client = {"scope":"login","client_ip":"::ffff:192.0.2.2","subject":"f"*64}
    guard = "/internal/rate/consume"
    assert request("POST", guard, client)[0] == 401
    assert request("POST", guard, client, "INTEGRATION")[0] == 403
    assert request("POST", guard, {**client,"scope":"coupon"}, "INTEGRATION")[0] == 200
    assert request("POST", guard, {**client,"scope":"landing"}, "INTEGRATION")[0] == 400

print("CGI smoke passed: authenticated configuration, 302/no-store, unchanged public page, and scoped deny/allow")
