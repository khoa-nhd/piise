"""
Scanner detector tests. Run:  PYTHONPATH=src python tests/test_scan.py
"""
from __future__ import annotations

from ttf.detectors import scan_text


def check(name: str, cond: bool) -> None:
    if not cond:
        raise AssertionError(f"FAILED: {name}")
    print(f"  ok  {name}")


SAMPLE = '''\
import hashlib
API_KEY = "sk_live_supersecret_value_123456"
def h(p): return hashlib.md5(p.encode()).hexdigest()

@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    return db.query("SELECT * FROM users WHERE id = " + str(user_id))

cursor.execute(f"SELECT * FROM orders WHERE id={oid}")
app.run(debug=True)
headers = {"Access-Control-Allow-Origin": "*"}
jwt.decode(tok, verify=False)
'''


def test_detectors_fire():
    fs = scan_text(SAMPLE, "sample.py")
    classes = {f.vuln_class for f in fs}
    check("secret detected", "Secrets exposure" in classes)
    check("sql injection detected", "Injection (SQL)" in classes)
    check("idor route heuristic detected",
          "Broken Object Level Authorization (IDOR)" in classes)
    check("weak hash detected", "Weak hashing" in classes)
    check("debug config detected", "Insecure configuration" in classes)
    check("cors wildcard detected", "CORS misconfiguration" in classes)
    check("jwt weak detected", "Authentication weakness" in classes)


def test_secret_is_masked():
    fs = scan_text('password = "abcdef_this_is_secret_1234"', "x.py")
    secret_findings = [f for f in fs if "Secrets" in f.vuln_class]
    check("a secret finding exists", len(secret_findings) == 1)
    ev = secret_findings[0].evidence
    check("raw secret NOT stored", "abcdef_this_is_secret_1234" not in ev)
    check("mask marker present", "***" in ev)


def test_all_potential_and_tagged():
    fs = scan_text(SAMPLE, "sample.py")
    check("every scan finding is POTENTIAL",
          all(f.exploitability.value == "POTENTIAL" for f in fs))
    check("every scan finding tagged static-scan",
          all("static-scan" in f.tags for f in fs))
    check("stable ids are unique", len({f.id for f in fs}) == len(fs))


def main():
    for fn in [test_detectors_fire, test_secret_is_masked, test_all_potential_and_tagged]:
        print(fn.__name__)
        fn()
    print("\nALL SCANNER TESTS PASSED")


if __name__ == "__main__":
    main()
