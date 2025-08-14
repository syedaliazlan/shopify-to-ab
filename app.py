import os
import hmac
import hashlib
import base64
import json
import time
from flask import Flask, request, abort, jsonify
import requests
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# Env
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
SHOPIFY_STORE_DOMAIN = os.getenv("SHOPIFY_STORE_DOMAIN")
SHOPIFY_PUBLIC_DOMAIN = os.getenv("SHOPIFY_PUBLIC_DOMAIN", SHOPIFY_STORE_DOMAIN)
SHOPIFY_ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN")
AB_API_KEY = os.getenv("AB_API_KEY")
DEFAULT_PRICE_RANGE_ID = os.getenv("DEFAULT_PRICE_RANGE_ID")
WEBHOOK_CALLBACK_URL = os.getenv("WEBHOOK_CALLBACK_URL")

SHOPIFY_API_VERSION = "2023-10"
HEADERS = {
    "Content-Type": "application/json",
    "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
}
REST_BASE = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"

SMART_COLLECTION_ID = "676440899969"

# --- Debounce: now keyed by (pid, topic) and 30s window ---
recently_handled = {}
DEBOUNCE_WINDOW = 30

def is_debounced(pid, topic):
    now = time.time()
    key = f"{pid}:{topic}"
    if key in recently_handled and now - recently_handled[key] < DEBOUNCE_WINDOW:
        return True
    recently_handled[key] = now
    return False

# ---------- Webhook registration helpers ----------
@app.route("/register_webhook", methods=["GET"])
def register_webhook():
    topics = ["products/create", "products/update"]
    results = []

    # fetch existing webhooks and avoid duplicates
    existing = requests.get(f"{REST_BASE}/webhooks.json", headers=HEADERS).json().get("webhooks", [])
    for topic in topics:
        if any(w["topic"] == topic and w["address"] == f"{WEBHOOK_CALLBACK_URL}/webhook/products" for w in existing):
            results.append({"topic": topic, "status": "exists"})
            continue
        payload = {
            "webhook": {
                "topic": topic,
                "address": f"{WEBHOOK_CALLBACK_URL}/webhook/products",
                "format": "json"
            }
        }
        url = f"{REST_BASE}/webhooks.json"
        response = requests.post(url, headers=HEADERS, json=payload)
        results.append({"topic": topic, "status": response.status_code, "body": response.json()})
    return jsonify(results), 200

# Quick audit endpoint to list and optionally clean duplicates
@app.route("/webhooks_audit", methods=["POST"])
def webhooks_audit():
    """
    Body: {"fix": true|false}
    If fix=true, keeps one webhook per topic to our address and deletes the rest.
    """
    data = request.get_json(silent=True) or {}
    fix = bool(data.get("fix"))
    target = f"{WEBHOOK_CALLBACK_URL}/webhook/products"

    res = requests.get(f"{REST_BASE}/webhooks.json", headers=HEADERS).json()
    webhooks = res.get("webhooks", [])
    report = {}

    for topic in ("products/create", "products/update"):
        matches = [w for w in webhooks if w["topic"] == topic and w["address"] == target]
        report[topic] = [{"id": w["id"], "address": w["address"]} for w in matches]
        if fix and len(matches) > 1:
            # keep the newest, delete the older ones
            keep = max(matches, key=lambda w: w["created_at"])
            for w in matches:
                if w["id"] != keep["id"]:
                    requests.delete(f"{REST_BASE}/webhooks/{w['id']}.json", headers=HEADERS)

    return jsonify({"fixed": fix, "report": report}), 200

# ---------- Shopify helpers ----------
def fetch_product(pid):
    return requests.get(f"{REST_BASE}/products/{pid}.json", headers=HEADERS).json().get("product")

def fetch_metafields(pid):
    return requests.get(f"{REST_BASE}/products/{pid}/metafields.json", headers=HEADERS).json().get("metafields", [])

def create_metafield(pid, namespace, key, type_, value):
    return requests.post(
        f"{REST_BASE}/products/{pid}/metafields.json",
        headers=HEADERS,
        json={"metafield": {"namespace": namespace, "key": key, "type": type_, "value": value}}
    )

def get_metafield_value(metafields, namespace, key, default=None):
    for m in metafields:
        if m.get("namespace") == namespace and m.get("key") == key:
            return m.get("value")
    return default

def delete_metafield(pid, mf_id):
    requests.delete(f"{REST_BASE}/products/{pid}/metafields/{mf_id}.json", headers=HEADERS)
    print(f"🗑️ Removed metafield {mf_id} from product {pid}")

def clear_ab_metafields(pid):
    for mf in fetch_metafields(pid):
        if mf['namespace'] == 'custom' and mf['key'] in ['ab_product_id','published_on_ab','last_synced_hash','ab_sync_status']:
            delete_metafield(pid, mf['id'])

# ---------- AB helpers ----------
def check_ab_product_exists(ab_id):
    r = requests.get(f"https://api.antiquesboutique.com/product/{ab_id}?sAPIKey={AB_API_KEY}")
    return r.status_code == 200 and r.json().get("status") == "success"

def delete_ab_product(ab_id):
    r = requests.delete(f"https://api.antiquesboutique.com/product/{ab_id}?sAPIKey={AB_API_KEY}")
    print("🗑️ Deleted AB product" if r.status_code == 200 else f"❌ AB delete failed {r.status_code}")

# ---------- Hash ----------
def compute_product_hash(prod):
    mf = prod.get("metafields", [])
    getm = lambda k: get_metafield_value(mf, "custom", k, "")
    images = [img.get("src","") for img in (prod.get("images") or [])][:20]
    if not images:
        main_img = prod.get("image",{}).get("src","")
        images = [main_img] if main_img else []
    rd = {
        "title": prod.get("title",""),
        "body_html": prod.get("body_html",""),
        "price": prod.get("variants",[{}])[0].get("price",""),
        "images": images,
        "handle": prod.get("handle",""),
        "ab_category": getm("ab_category"),
        "ab_period": getm("ab_period"),
        "ab_item_nationality": getm("ab_item_nationality")
    }
    return hashlib.sha256(json.dumps(rd, sort_keys=True).encode()).hexdigest()

# ---------- Sync to AB ----------
def send_to_ab(prod, ab_id=None):
    mf = prod.get("metafields", [])
    getm = lambda k: get_metafield_value(mf, "custom", k, None)
    price = prod.get("variants",[{}])[0].get("price")
    sku = prod.get("variants",[{}])[0].get("sku")

    if not price and not DEFAULT_PRICE_RANGE_ID:
        print("❌ Missing price")
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

    # Images (1..20)
    gallery = [img.get("src","") for img in (prod.get("images") or []) if img.get("src")]
    if not gallery:
        main_img = prod.get("image",{}).get("src")
        if main_img:
            gallery = [main_img]
    for idx, url in enumerate(gallery[:20], start=1):
        d[f"sImageURL_{idx}"] = url

    # External URL
    handle = prod.get("handle")
    if handle:
        d["sExternalURL"] = f"https://{SHOPIFY_PUBLIC_DOMAIN}/products/{handle}"

    r = requests.post(
        f"https://api.antiquesboutique.com/product/{ab_id or ''}?sAPIKey={AB_API_KEY}",
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        data=d
    )

    if r.status_code == 200:
        if not ab_id:
            new = r.json().get("nShopProd_ID")
            if new:
                create_metafield(prod['id'], "custom", "ab_product_id", "single_line_text_field", str(new))
                create_metafield(prod['id'], "custom", "published_on_ab", "boolean", "true")
        h = compute_product_hash(prod)
        create_metafield(prod['id'], "custom", "last_synced_hash", "single_line_text_field", h)
    else:
        print("❌ AB sync error:", r.text)

# ---------- Webhook listener ----------
@app.route("/webhook/products", methods=["POST"])
def handle_webhook():
    data = request.get_data()
    digest = hmac.new(SHOPIFY_API_SECRET.encode(), data, hashlib.sha256).digest()
    if not hmac.compare_digest(base64.b64encode(digest).decode(), request.headers.get("X-Shopify-Hmac-Sha256")):
        abort(401)

    payload = json.loads(data)
    pid = payload.get("id")
    topic = request.headers.get("X-Shopify-Topic")

    if is_debounced(pid, topic):
        return "Debounced", 200

    prod = fetch_product(pid)
    prod["metafields"] = fetch_metafields(pid)

    tags = (prod.get("tags") or "").lower()
    status = prod.get("status")
    inv = sum(v.get("inventory_quantity",0) for v in prod.get("variants",[]))

    abmf_val = get_metafield_value(prod["metafields"], "custom", "ab_product_id")
    published_val = get_metafield_value(prod["metafields"], "custom", "published_on_ab")
    sync_status = get_metafield_value(prod["metafields"], "custom", "ab_sync_status")  # "creating" guard

    if topic == "products/create":
        time.sleep(3)
        if abmf_val:
            print("⛔️ Already on AB")
        elif sync_status == "creating":
            print("⏳ AB create in progress — skipping duplicate create")
        elif status == "active" and "old" in tags and inv > 0 and (not published_val or published_val != "true"):
            print("✅ Creating new AB product")
            # set lock *before* calling AB to prevent races
            create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "creating")
            try:
                send_to_ab(prod)
            finally:
                # clear the lock regardless; send_to_ab writes the ID on success
                create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "")
        else:
            print("⛔️ Create criteria not met")

    else:  # products/update
        # deletion rules
        if abmf_val and ("old" not in tags or status == "draft" or inv <= 0):
            if check_ab_product_exists(abmf_val):
                delete_ab_product(abmf_val)
            clear_ab_metafields(pid)
            return "Deleted from AB", 200

        # skip recreation while a create is in-flight
        if sync_status == "creating":
            print("⏳ AB create in progress — skipping update/recreate")
            return "Create in progress", 200

        # recreate when back in qualifying state
        if not abmf_val and status == "active" and "old" in tags and inv > 0:
            print("🔁 Recreating product on AB")
            create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "creating")
            try:
                send_to_ab(prod)
            finally:
                create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "")
            return "Recreated on AB", 200

        # normal update
        last = get_metafield_value(prod["metafields"], "custom", "last_synced_hash")
        new_hash = compute_product_hash(prod)
        if new_hash != last and abmf_val and "old" in tags and status == "active" and inv > 0:
            print("🔄 Updating AB product")
            send_to_ab(prod, ab_id=abmf_val)
        else:
            print("⛔️ No AB update or sync needed")

    return "Webhook processed", 200

# ---------- Run ----------
if __name__ == "__main__":
    app.run()
