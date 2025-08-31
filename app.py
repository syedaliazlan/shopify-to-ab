import os
import hmac
import hashlib
import base64
import json
import time
import threading
from flask import Flask, request, abort, jsonify
import requests
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# Load environment variables
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
SHOPIFY_STORE_DOMAIN = os.getenv("SHOPIFY_STORE_DOMAIN")
SHOPIFY_ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN")
AB_API_KEY = os.getenv("AB_API_KEY")
DEFAULT_PRICE_RANGE_ID = os.getenv("DEFAULT_PRICE_RANGE_ID")
WEBHOOK_CALLBACK_URL = os.getenv("WEBHOOK_CALLBACK_URL")

SHOPIFY_API_VERSION = "2025-04"
HEADERS = {
    "Content-Type": "application/json",
    "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
}
REST_BASE = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"

recently_handled = {}

# Simple debouncer to avoid duplicate processing
def is_debounced(pid):
    now = time.time()
    if pid in recently_handled and now - recently_handled[pid] < 15:
        return True
    recently_handled[pid] = now
    return False

# Generate hash of relevant product data for change tracking
def compute_product_hash(prod):
    mf = prod.get("metafields", [])
    getm = lambda k: next((m['value'] for m in mf if m['namespace']=='custom' and m['key']==k), "")
    rd = {
        "title": prod.get("title",""),
        "body_html": prod.get("body_html",""),
        "price": prod.get("variants",[{}])[0].get("price",""),
        "images": sorted([img.get('src', '') for img in prod.get("images", [])]),
        "ab_category": getm("ab_category"),
        "ab_period": getm("ab_period"),
        "ab_item_nationality": getm("ab_item_nationality")
    }
    return hashlib.sha256(json.dumps(rd, sort_keys=True).encode()).hexdigest()

# Shopify API helpers
def fetch_product(pid):
    return requests.get(f"{REST_BASE}/products/{pid}.json", headers=HEADERS).json().get("product")

def fetch_metafields(pid):
    return requests.get(f"{REST_BASE}/products/{pid}/metafields.json", headers=HEADERS).json().get("metafields", [])

def set_metafield(pid, data):
    """Helper to create/update a metafield."""
    requests.post(
        f"{REST_BASE}/products/{pid}/metafields.json",
        headers=HEADERS,
        json={"metafield": data}
    )

def delete_metafield(pid, mf_id):
    requests.delete(f"{REST_BASE}/products/{pid}/metafields/{mf_id}.json", headers=HEADERS)
    print(f"🗑️ Removed metafield {mf_id} from product {pid}")

def clear_ab_metafields(pid):
    for mf in fetch_metafields(pid):
        if mf['namespace'] == 'custom' and mf['key'] in ['ab_product_id','published_on_ab','last_synced_hash']:
            delete_metafield(pid, mf['id'])

# Antiques Boutique API helpers
def check_ab_product_exists(ab_id):
    r = requests.get(f"https://api.antiquesboutique.com/product/{ab_id}?sAPIKey={AB_API_KEY}")
    return r.status_code == 200 and r.json().get("status") == "success"

def delete_ab_product(ab_id):
    r = requests.delete(f"https://api.antiquesboutique.com/product/{ab_id}?sAPIKey={AB_API_KEY}")
    print("🗑️ Deleted AB product" if r.status_code == 200 else f"❌ AB delete failed {r.status_code}")

def send_to_ab(prod, ab_id=None):
    """This function runs in a background thread and handles the slow API call."""
    pid = prod['id']
    print(f"BACKGROUND: Starting sync for product {pid}...")
    mf = prod.get("metafields", [])
    getm = lambda k: next((m['value'] for m in mf if m['namespace']=='custom' and m['key']==k), None)
    price = prod.get("variants",[{}])[0].get("price")
    sku = prod.get("variants",[{}])[0].get("sku")

    if not price and not DEFAULT_PRICE_RANGE_ID:
        print(f"BACKGROUND: ❌ Missing price for product {pid}. Aborting.")
        return

    d = {
        "sRef": sku, "sShopProdName": prod["title"], "sDescription": prod["body_html"],
        "nShopProdCat_ID_1": getm("ab_category"), "nShopProdPeriod_ID": getm("ab_period"),
        "nNationality_ID": getm("ab_item_nationality")
    }

    if price: d["nPrice"] = float(price)
    else: d["nShopProdPriceRange_ID"] = int(DEFAULT_PRICE_RANGE_ID)

    if prod.get("handle"): d["sExternalURL"] = f"https://{SHOPIFY_STORE_DOMAIN}/products/{prod['handle']}"

    images = prod.get("images", [])
    if images:
        for i, image in enumerate(images[:20], 1):
            image_url = image.get("src")
            if image_url: d[f"sImageURL_{i}"] = image_url

    try:
        r = requests.post(
            f"https://api.antiquesboutique.com/product/{ab_id or ''}?sAPIKey={AB_API_KEY}",
            headers={"Content-Type":"application/x-www-form-urlencoded"}, data=d, timeout=120
        )
        r.raise_for_status()
        response_json = r.json()

        if response_json.get("status") == "success":
            print(f"BACKGROUND: ✅ Successfully received response from AB for product {pid}.")
            # Set all metafields now that we have a successful response
            if not ab_id:
                new_ab_id = response_json.get("nShopProd_ID")
                if new_ab_id:
                    set_metafield(pid, {"namespace": "custom", "key": "ab_product_id", "type": "single_line_text_field", "value": str(new_ab_id)})
            
            set_metafield(pid, {"namespace": "custom", "key": "published_on_ab", "type": "boolean", "value": "true"})
            new_hash = compute_product_hash(prod)
            set_metafield(pid, {"namespace": "custom", "key": "last_synced_hash", "type": "single_line_text_field", "value": new_hash})
            print(f"BACKGROUND: ✅ Set all metafields for product {pid}.")
        else:
            print(f"BACKGROUND: ❌ AB API returned failure for {pid}: {response_json.get('message')}")

    except requests.exceptions.RequestException as e:
        print(f"BACKGROUND: ❌ AB sync error (Request Exception) for {pid}: {e}")

# Webhook listener
@app.route("/webhook/products", methods=["POST"])
def handle_webhook():
    data = request.get_data()
    digest = hmac.new(SHOPIFY_API_SECRET.encode(), data, hashlib.sha256).digest()
    if not hmac.compare_digest(base64.b64encode(digest).decode(), request.headers.get("X-Shopify-Hmac-Sha256")):
        abort(401)

    payload = json.loads(data)
    pid = payload.get("id")
    if is_debounced(pid):
        return "Debounced", 200

    # Fetch fresh product data from Shopify
    prod = fetch_product(pid)
    if not prod: return "Product not found.", 404
    prod["metafields"] = fetch_metafields(pid)

    tags = prod.get("tags","").lower()
    status = prod.get("status")
    inv = sum(v.get("inventory_quantity",0) for v in prod.get("variants",[]))
    abmf = next((m for m in prod["metafields"] if m["namespace"]=="custom" and m["key"]=="ab_product_id"), {})
    
    # --- Deletion Logic (Synchronous) ---
    # If the product exists on AB but no longer meets criteria, delete it.
    if abmf.get("value") and ("old" not in tags or status == "draft" or inv <= 0):
        print(f"🗑️ Product {pid} no longer meets criteria. Deleting from AB.")
        if check_ab_product_exists(abmf["value"]):
            delete_ab_product(abmf["value"])
        clear_ab_metafields(pid)
        return "Product deleted from AB", 200

    # --- Sync Logic (Asynchronous) ---
    should_sync = status == "active" and "old" in tags and inv > 0
    if not should_sync:
        return "Product does not meet sync criteria", 200

    ab_id_val = abmf.get("value")
    
    # Case 1: Needs to be created
    if not ab_id_val:
        print(f"🚀 Spawning background thread to CREATE product {pid} on AB.")
        thread = threading.Thread(target=send_to_ab, args=(prod,))
        thread.start()
        return "Accepted for creation", 202

    # Case 2: Needs to be updated
    last_hash = next((m["value"] for m in prod["metafields"] if m["namespace"]=="custom" and m["key"]=="last_synced_hash"), None)
    new_hash = compute_product_hash(prod)
    if new_hash != last_hash:
        print(f"🚀 Spawning background thread to UPDATE product {pid} on AB.")
        thread = threading.Thread(target=send_to_ab, args=(prod,), kwargs={'ab_id': ab_id_val})
        thread.start()
        return "Accepted for update", 202

    return "No changes detected; sync not required", 200

# This endpoint is only for convenience if you want to manually register webhooks.
@app.route("/register_webhook", methods=["GET"])
def register_webhook():
    if not (SHOPIFY_ACCESS_TOKEN and SHOPIFY_STORE_DOMAIN and WEBHOOK_CALLBACK_URL):
        return "Missing env vars (token/domain/callback).", 500

    api_version = "2025-04"  # update from 2023-10
    base = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{api_version}"
    h = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
    }

    # Read existing webhooks so we can upsert
    try:
        existing = requests.get(f"{base}/webhooks.json", headers=h, timeout=15).json().get("webhooks", [])
    except Exception as e:
        return f"Failed to read existing webhooks: {e}", 500

    desired = [
        {"topic": "products/create", "address": f"{WEBHOOK_CALLBACK_URL}/webhook/products", "format": "json"},
        {"topic": "products/update", "address": f"{WEBHOOK_CALLBACK_URL}/webhook/products", "format": "json"},
        {"topic": "products/delete", "address": f"{WEBHOOK_CALLBACK_URL}/webhook/products", "format": "json"},
    ]

    def ensure_webhook(d):
        # If a matching topic+address exists, do nothing
        for w in existing:
            if w.get("topic") == d["topic"] and w.get("address") == d["address"]:
                return f"OK (exists): {d['topic']}"
        # Otherwise create it
        r = requests.post(f"{base}/webhooks.json", headers=h, json={"webhook": d}, timeout=15)
        if r.status_code in (201, 202):
            return f"Created: {d['topic']}"
        return f"Create failed {d['topic']}: {r.status_code} {r.text}"

    results = [ensure_webhook(d) for d in desired]
    return "; ".join(results), 200

if __name__ == "__main__":
    app.run()