"""Test traffic generator for the demo: a mix of normal and problematic requests through mitmproxy.

Run from the Mac (only python3 is needed, nothing to install):
  python3 tools/traffic.py            # 3 rounds
  python3 tools/traffic.py -n 10      # 10 rounds
  python3 tools/traffic.py -p 0.5     # pause between requests, seconds

One round = normal student activity plus a few "bad" events. The agent gets everything
together, unlabeled, and has to tell normal from problematic on its own.

  normal:    GET /api/health, /api/schedule, /api/courses (200),
             POST /login (200) and GET /api/grades with a token (200)
  noise:     POST /login with an empty password (401), GET /api/grades without a token (401),
             GET /nope (404)
  transport: password and token travel over HTTP (clear text);
             HTTPS where the client ignores the certificate (MITM decrypts it);
             HTTPS where the client rejects the certificate (tls_client_rejected)

All data is fake (student / demo-password).
"""
import argparse
import json
import ssl
import time
import urllib.error
import urllib.request

HTTP = "http://localhost:8082"
HTTPS = "https://localhost:8083"
TOKEN = "demo-token-123"


def call(method, url, body=None, token=None, verify=True):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            return r.status
    except urllib.error.HTTPError as e:  # 401/404 are server responses, not failures
        return e.code


GOOD_LOGIN = {"username": "student", "password": "demo-password"}
BAD_LOGIN = {"username": "student", "password": ""}  # empty password: the server answers 401

# (label for the terminal, method, url, body, token, verify_certificate)
STEPS = [
    ("health",                            "GET",  f"{HTTP}/api/health",   None,       None,  True),
    ("schedule",                          "GET",  f"{HTTP}/api/schedule", None,       None,  True),
    ("courses",                           "GET",  f"{HTTP}/api/courses",  None,       None,  True),
    ("login (HTTP)",                      "POST", f"{HTTP}/login",        GOOD_LOGIN, None,  True),
    ("grades with token (HTTP)",          "GET",  f"{HTTP}/api/grades",   None,       TOKEN, True),
    ("login, empty password",             "POST", f"{HTTP}/login",        BAD_LOGIN,  None,  True),
    ("grades without token",              "GET",  f"{HTTP}/api/grades",   None,       None,  True),
    ("nonexistent path",                  "GET",  f"{HTTP}/nope",         None,       None,  True),
    ("HTTPS, certificate ignored",        "POST", f"{HTTPS}/login",       GOOD_LOGIN, None,  False),
    ("HTTPS, certificate verified",       "POST", f"{HTTPS}/login",       GOOD_LOGIN, None,  True),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=3, help="number of rounds")
    ap.add_argument("-p", type=float, default=0.5, help="pause between requests, seconds")
    args = ap.parse_args()

    for i in range(1, args.n + 1):
        print(f"--- round {i}/{args.n} ---")
        for name, method, url, body, token, verify in STEPS:
            try:
                print(f"  {name}: {call(method, url, body, token, verify)}")
            except Exception as exc:
                reason = getattr(exc, "reason", exc)
                print(f"  {name}: rejected ({reason})")
            time.sleep(args.p)


if __name__ == "__main__":
    main()
