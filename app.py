import os
import hmac
import hashlib
import base64
import json
import time
from flask import Flask, request, abort, jsonify
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# ── ENV ────────────────────────────────────────────────────────────────────────
SHOPIFY_API_SECRET   = os.getenv("SHOPIFY_API_SECRET")
SHOPIFY_STORE_DOMAIN = os.getenv("SHOPIFY_STORE_DOMAIN")          # admin domain
SHOPIFY_PUBLIC_DOMAIN= os.getenv("SHOPIFY_PUBLIC_DOMAIN", SHOPIFY_STORE_DOMAIN)  # public site (set this!)
SHOPIFY_ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN")
AB_API_KEY           = os.getenv("AB_API_KEY")
DEFAULT_PRICE_RANGE_ID = os.getenv("DEFAULT_PRICE_RANGE_ID")
WEBHOOK_CALLBACK_URL = os.getenv("WEBHOOK_CALLBACK_URL","").rstrip("/")  # normalize

SHOPIFY_API_VERSION = "2023-10"
HEADERS = {
    "Content-Type": "application/json",
    "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
}
REST_BASE = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"

# ── HTTP session with retries/timeouts ─────────────────────────────────────────
SESSION = requests.Session()
retries = Retry(
    total=3, backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods={"GET","POST","DELETE"}
)
SESSION.mount("https://", HTTPAdapter(max_retries=retries))
SESSION.mount("http://",  HTTPAdapter(max_retries=retries))
DEFAULT_TIMEOUT = (5, 25)  # (connect, read)

# ── State ──────────────────────────────────────────────────────────────────────
recently_handled = {}
DEBOUNCE_WINDOW = 30  # seconds

SMART_COLLECTION_ID = "676440899969"  # unchanged, not used in webhook flow

# ── Helpers: Debounce ──────────────────────────────────────────────────────────
def is_debounced(pid, topic):
    now = time.time()
    key = f"{pid}:{topic}"
    if key in recently_handled and now - recently_handled[key] < DEBOUNCE_WINDOW:
        return True
    recently_handled[key] = now
    return False

# ── Webhook registration & audit ───────────────────────────────────────────────
@app.route("/register_webhook", methods=["GET"])
def register_webhook():
    topics = ["products/create", "products/update"]
    results = []
    existing = SESSION.get(f"{REST_BASE}/webhooks.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT).json().get("webhooks", [])
    for topic in topics:
        addr = f"{WEBHOOK_CALLBACK_URL}/webhook/products"
        if any(w["topic"]==topic and w["address"]==addr for w in existing):
            results.append({"topic": topic, "status": "exists"})
            continue
        payload = {"webhook": {"topic": topic, "address": addr, "format": "json"}}
        resp = SESSION.post(f"{REST_BASE}/webhooks.json", headers=HEADERS, json=payload, timeout=DEFAULT_TIMEOUT)
        results.append({"topic": topic, "status": resp.status_code, "body": resp.json()})
    return jsonify(results), 200

@app.route("/webhooks_audit", methods=["POST"])
def webhooks_audit():
    data = request.get_json(silent=True) or {}
    fix = bool(data.get("fix"))
    addr = f"{WEBHOOK_CALLBACK_URL}/webhook/products"
    res = SESSION.get(f"{REST_BASE}/webhooks.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT).json()
    webhooks = res.get("webhooks", [])
    report = {}
    for topic in ("products/create","products/update"):
        matches = [w for w in webhooks if w["topic"]==topic and w["address"]==addr]
        report[topic] = [{"id": w["id"], "address": w["address"]} for w in matches]
        if fix and len(matches)>1:
            keep = max(matches, key=lambda w: w["created_at"])
            for w in matches:
                if w["id"] != keep["id"]:
                    SESSION.delete(f"{REST_BASE}/webhooks/{w['id']}.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT)
    return jsonify({"fixed": fix, "report": report}), 200

# ── Shopify helpers ────────────────────────────────────────────────────────────
def fetch_product(pid):
    return SESSION.get(f"{REST_BASE}/products/{pid}.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT).json().get("product")

def fetch_metafields(pid):
    return SESSION.get(f"{REST_BASE}/products/{pid}/metafields.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT).json().get("metafields", [])

def create_metafield(pid, namespace, key, type_, value):
    return SESSION.post(
        f"{REST_BASE}/products/{pid}/metafields.json",
        headers=HEADERS,
        json={"metafield": {"namespace": namespace, "key": key, "type": type_, "value": value}},
        timeout=DEFAULT_TIMEOUT
    )

def get_metafield_value(metafields, namespace, key, default=None):
    for m in metafields:
        if m.get("namespace")==namespace and m.get("key")==key:
            return m.get("value")
    return default

def delete_metafield(pid, mf_id):
    SESSION.delete(f"{REST_BASE}/products/{pid}/metafields/{mf_id}.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT)

def clear_ab_metafields(pid):
    for mf in fetch_metafields(pid):
        if mf['namespace']=="custom" and mf['key'] in {"ab_product_id","published_on_ab","last_synced_hash","ab_sync_status"}:
            delete_metafield(pid, mf['id'])

# ── AB helpers ─────────────────────────────────────────────────────────────────
def check_ab_product_exists(ab_id):
    r = SESSION.get(f"https://api.antiquesboutique.com/product/{ab_id}?sAPIKey={AB_API_KEY}", timeout=DEFAULT_TIMEOUT)
    return r.status_code == 200 and r.json().get("status") == "success"

def delete_ab_product(ab_id):
    r = SESSION.delete(f"https://api.antiquesboutique.com/product/{ab_id}?sAPIKey={AB_API_KEY}", timeout=DEFAULT_TIMEOUT)
    print("🗑️ Deleted AB product" if r.status_code == 200 else f"❌ AB delete failed {r.status_code}")

# ── Hash used to detect updates ────────────────────────────────────────────────
def compute_product_hash(prod):
    mf = prod.get("metafields", [])
    getm = lambda k: get_metafield_value(mf, "custom", k, "")
    images = [img.get("src","") for img in (prod.get("images") or [])][:20]
    if not images:
        main = prod.get("image",{}).get("src","")
        images = [main] if main else []
    rd = {
        "title": prod.get("title",""),
        "body_html": prod.get("body_html",""),
        "price": prod.get("variants",[{}])[0].get("price",""),
        "images": images,
        "handle": prod.get("handle",""),
        "ab_category": getm("ab_category"),
        "ab_period": getm("ab_period"),
        "ab_item_nationality": getm("ab_item_nationality"),
    }
    return hashlib.sha256(json.dumps(rd, sort_keys=True).encode()).hexdigest()

# ── Core: send to AB ───────────────────────────────────────────────────────────
def send_to_ab(prod, ab_id=None):
    mf = prod.get("metafields", [])
    getm = lambda k: get_metafield_value(mf, "custom", k, None)
    price = prod.get("variants",[{}])[0].get("price")
    sku   = prod.get("variants",[{}])[0].get("sku")

    if not price and not DEFAULT_PRICE_RANGE_ID:
        print("❌ Missing price and no DEFAULT_PRICE_RANGE_ID")
        return

    d = {
        "sRef": sku,
        "sShopProdName": prod["title"],
        "sDescription": prod["body_html"],
        "nShopProdCat_ID_1": getm("ab_category"),
        "nShopProdPeriod_ID": getm("ab_period"),
        "nNationality_ID": getm("ab_item_nationality")
    }
    if price:
        d["nPrice"] = float(price)
    else:
        d["nShopProdPriceRange_ID"] = int(DEFAULT_PRICE_RANGE_ID)

    # Images: first is mandatory; send up to 20
    gallery = [img.get("src","") for img in (prod.get("images") or []) if img.get("src")]
    if not gallery:
        main = prod.get("image",{}).get("src")
        if main: gallery = [main]
    for idx, url in enumerate(gallery[:20], start=1):
        d[f"sImageURL_{idx}"] = url

    # External URL — use PUBLIC domain (set SHOPIFY_PUBLIC_DOMAIN env)
    handle = prod.get("handle")
    if handle:
        d["sExternalURL"] = f"https://{SHOPIFY_PUBLIC_DOMAIN}/products/{handle}"

    # POST to AB
    r = SESSION.post(
        f"https://api.antiquesboutique.com/product/{ab_id or ''}?sAPIKey={AB_API_KEY}",
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        data=d,
        timeout=DEFAULT_TIMEOUT
    )
    if r.status_code != 200:
        print("❌ AB sync error:", r.text)
        return None

    return r.json()

# ── Webhook listener ───────────────────────────────────────────────────────────
@app.route("/webhook/products", methods=["POST"])
def handle_webhook():
    # HMAC verify
    data = request.get_data()
    digest = hmac.new(SHOPIFY_API_SECRET.encode(), data, hashlib.sha256).digest()
    if not hmac.compare_digest(base64.b64encode(digest).decode(), request.headers.get("X-Shopify-Hmac-Sha256","")):
        abort(401)

    payload = json.loads(data)
    pid = payload.get("id")
    topic = request.headers.get("X-Shopify-Topic","")

    if is_debounced(pid, topic):
        return "Debounced", 200

    prod = fetch_product(pid)
    prod["metafields"] = fetch_metafields(pid)

    tags = (prod.get("tags") or "").lower()
    status = prod.get("status")
    inv = sum(v.get("inventory_quantity",0) for v in prod.get("variants",[]))

    ab_id   = get_metafield_value(prod["metafields"], "custom", "ab_product_id")
    pub_val = get_metafield_value(prod["metafields"], "custom", "published_on_ab")
    lock    = get_metafield_value(prod["metafields"], "custom", "ab_sync_status")

    if topic == "products/create":
        time.sleep(3)  # give Shopify a sec to finish writing images, etc.
        if ab_id:
            print("⛔️ Already on AB")
        elif lock == "creating":
            print("⏳ Create in progress — skipping duplicate create")
        elif status=="active" and "old" in tags and inv>0 and (not pub_val or pub_val!="true"):
            print("✅ Creating new AB product")
            create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "creating")
            try:
                resp = send_to_ab(prod)
                if resp and resp.get("nShopProd_ID"):
                    create_metafield(pid, "custom", "ab_product_id", "single_line_text_field", str(resp["nShopProd_ID"]))
                    create_metafield(pid, "custom", "published_on_ab", "boolean", "true")
                    h = compute_product_hash(prod)
                    create_metafield(pid, "custom", "last_synced_hash", "single_line_text_field", h)
                else:
                    print("⚠️ AB did not return nShopProd_ID")
            finally:
                create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "")
        else:
            print("⛔️ Create criteria not met")

    else:  # products/update
        # Deletion rules
        if ab_id and ("old" not in tags or status=="draft" or inv<=0):
            if check_ab_product_exists(ab_id):
                delete_ab_product(ab_id)
            clear_ab_metafields(pid)
            return "Deleted from AB", 200

        # Skip updates while a create is in-flight
        if lock == "creating":
            print("⏳ Create in progress — skipping update/recreate")
            return "Create in progress", 200

        # Recreate when back in qualifying state
        if not ab_id and status=="active" and "old" in tags and inv>0:
            print("🔁 Recreating product on AB")
            create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "creating")
            try:
                resp = send_to_ab(prod)
                if resp and resp.get("nShopProd_ID"):
                    create_metafield(pid, "custom", "ab_product_id", "single_line_text_field", str(resp["nShopProd_ID"]))
                    create_metafield(pid, "custom", "published_on_ab", "boolean", "true")
                    h = compute_product_hash(prod)
                    create_metafield(pid, "custom", "last_synced_hash", "single_line_text_field", h)
            finally:
                create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "")
            return "Recreated on AB", 200

        # Normal update when material fields (incl. images/URL) changed
        last = get_metafield_value(prod["metafields"], "custom", "last_synced_hash")
        new_hash = compute_product_hash(prod)
        if new_hash != last and ab_id and "old" in tags and status=="active" and inv>0:
            print("🔄 Updating AB product")
            resp = send_to_ab(prod, ab_id=ab_id)
            if resp:  # on success, store new hash
                create_metafield(pid, "custom", "last_synced_hash", "single_line_text_field", new_hash)
        else:
            print("⛔️ No AB update or sync needed")

    return "Webhook processed", 200

# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # If you control gunicorn, also set a sensible worker timeout (e.g., 60s)
    app.run()
