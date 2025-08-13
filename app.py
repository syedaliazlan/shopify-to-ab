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

# Load environment variables
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
SHOPIFY_STORE_DOMAIN = os.getenv("SHOPIFY_STORE_DOMAIN")
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
recently_handled = {}

# Register webhook endpoint
@app.route("/register_webhook", methods=["GET"])
def register_webhook():
    topics = ["products/create", "products/update"]
    results = []
    for topic in topics:
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
    # include first 20 image URLs so image changes cause an update
    images = [img.get("src","") for img in (prod.get("images") or [])][:20]
    if not images:
        # fallback to main image if gallery empty
        main_img = prod.get("image",{}).get("src","")
        images = [main_img] if main_img else []
    rd = {
        "title": prod.get("title",""),
        "body_html": prod.get("body_html",""),
        "price": prod.get("variants",[{}])[0].get("price",""),
        "images": images,
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
    mf = prod.get("metafields", [])
    getm = lambda k: next((m['value'] for m in mf if m['namespace']=='custom' and m['key']==k), None)
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

    # --- NEW: map full gallery images to sImageURL_1..20 (first required) ---
    # Prefer gallery; if empty, fallback to main image.
    gallery = [img.get("src","") for img in (prod.get("images") or []) if img.get("src")]
    if not gallery:
        main_img = prod.get("image",{}).get("src")
        if main_img:
            gallery = [main_img]

    # Set up to 20 images per AB docs
    for idx, url in enumerate(gallery[:20], start=1):
        d[f"sImageURL_{idx}"] = url
    # ------------------------------------------------------------------------

    r = requests.post(
        f"https://api.antiquesboutique.com/product/{ab_id or ''}?sAPIKey={AB_API_KEY}",
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        data=d
    )

    if r.status_code == 200:
        if not ab_id:
            new = r.json().get("nShopProd_ID")
            if new:
                requests.post(
                    f"{REST_BASE}/products/{prod['id']}/metafields.json",
                    headers=HEADERS,
                    json={"metafield": {"namespace": "custom", "key": "ab_product_id", "type": "single_line_text_field", "value": str(new)}}
                )
                requests.post(
                    f"{REST_BASE}/products/{prod['id']}/metafields.json",
                    headers=HEADERS,
                    json={"metafield": {"namespace": "custom", "key": "published_on_ab", "type": "boolean", "value": "true"}}
                )
        h = compute_product_hash(prod)
        requests.post(
            f"{REST_BASE}/products/{prod['id']}/metafields.json",
            headers=HEADERS,
            json={"metafield": {"namespace": "custom", "key": "last_synced_hash", "type": "single_line_text_field", "value": h}}
        )
    else:
        print("❌ AB sync error:", r.text)

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

    prod = fetch_product(pid)
    prod["metafields"] = fetch_metafields(pid)

    tags = prod.get("tags","").lower()
    status = prod.get("status")
    inv = sum(v.get("inventory_quantity",0) for v in prod.get("variants",[]))
    abmf = next((m for m in prod["metafields"] if m["namespace"]=="custom" and m["key"]=="ab_product_id"), {})
    published = next((m for m in prod["metafields"] if m["namespace"]=="custom" and m["key"]=="published_on_ab"), {})

    topic = request.headers.get("X-Shopify-Topic")
    if topic == "products/create":
        time.sleep(3)
        if abmf.get("value"):
            print("⛔️ Already on AB")
        elif status=="active" and "old" in tags and inv>0 and (not published.get("value") or published["value"]!="true"):
            print("✅ Creating new AB product")
            send_to_ab(prod)
        else:
            print("⛔️ Create criteria not met")

    else:  # products/update
        if abmf.get("value") and ("old" not in tags or status=="draft" or inv<=0):
            if check_ab_product_exists(abmf["value"]):
                delete_ab_product(abmf["value"])
            clear_ab_metafields(pid)
            return "Deleted from AB", 200

        if not abmf.get("value") and status=="active" and "old" in tags and inv>0:
            print("🔁 Recreating product on AB")
            send_to_ab(prod)
            return "Recreated on AB", 200

        last = next((m["value"] for m in prod["metafields"] if m["namespace"]=="custom" and m["key"]=="last_synced_hash"), None)
        new_hash = compute_product_hash(prod)
        if new_hash != last and abmf.get("value") and "old" in tags and status=="active" and inv>0:
            print("🔄 Updating AB product")
            send_to_ab(prod, ab_id=abmf["value"])
        else:
            print("⛔️ No AB update or sync needed")

    return "Webhook processed", 200

# Start Flask app
if __name__ == "__main__":
    app.run()
