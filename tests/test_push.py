
import urllib.request, urllib.parse, http.cookiejar, json

BASE = "http://127.0.0.1:8899"
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def post(path, data=None):
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(f"{BASE}{path}", data=body, method="POST",
                                 headers={"Content-Type":"application/json"} if body else {})
    with opener.open(req, timeout=15) as r:
        return r.status, json.loads(r.read())

def get(path):
    with opener.open(f"{BASE}{path}", timeout=15) as r:
        return r.status, json.loads(r.read())

# Login
print("Login...")
post("/api/login", {"username":"admin", "password":"admin123"})
print("OK")

# vapid-public-key
st, data = get("/api/push/vapid-public-key")
print(f"vapid-public-key: HTTP {st}, key length={len(data.get('public_key',''))}")
assert st == 200, f"expected 200, got {st}"
assert len(data['public_key']) > 50, "key zu kurz"

# subscribe
test_sub = {
    "endpoint": "https://fcm.googleapis.com/fcm/send/test123",
    "p256dh": "test_p256dh",
    "auth": "test_auth"
}
st, data = post("/api/push/subscribe", test_sub)
print(f"subscribe: HTTP {st}")
assert st == 200, f"expected 200, got {st}"

# unsubscribe
st, data = post("/api/push/unsubscribe", {})
print(f"unsubscribe: HTTP {st}")
assert st == 200, f"expected 200, got {st}"

print("Push-Tests BESTANDEN ✅")
