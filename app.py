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

SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY")
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
SHOPIFY_STORE_DOMAIN = os.getenv("SHOPIFY_STORE_DOMAIN")
SHOPIFY_ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN")
WEBHOOK_CALLBACK_URL = os.getenv("WEBHOOK_CALLBACK_URL")
AB_API_KEY = os.getenv("AB_API_KEY")
DEFAULT_PRICE_RANGE_ID = os.getenv("DEFAULT_PRICE_RANGE_ID")

SHOPIFY_API_VERSION = "2023-10"
HEADERS = {
    "Content-Type": "application/json",
    "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
}

SMART_COLLECTION_ID = "676440899969"
recently_handled = {}

def is_debounced(product_id):
    now = time.time()
    if product_id in recently_handled and now - recently_handled[product_id] < 15:
        return True
    recently_handled[product_id] = now
    return False

def compute_product_hash(product):
    metafields = product.get("metafields", [])
    get_meta = lambda key: next((m['value'] for m in metafields if m['namespace'] == 'custom' and m['key'] == key), "")

    relevant_data = {
        "title": product.get("title", ""),
        "body_html": product.get("body_html", ""),
        "price": product.get("variants", [{}])[0].get("price", ""),
        "image": product.get("image", {}).get("src", ""),
        "ab_category": get_meta("ab_category"),
        "ab_period": get_meta("ab_period"),
        "ab_item_nationality": get_meta("ab_item_nationality")
    }

    hash_input = json.dumps(relevant_data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(hash_input).hexdigest()

@app.route("/register_webhook", methods=["GET"])
def register_webhook():
    topics = ["products/update", "products/create"]
    results = []
    for topic in topics:
        webhook_payload = {
            "webhook": {
                "topic": topic,
                "address": f"{WEBHOOK_CALLBACK_URL}/webhook/products",
                "format": "json"
            }
        }
        url = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/webhooks.json"
        response = requests.post(url, headers=HEADERS, json=webhook_payload)
        results.append({"topic": topic, "status": response.status_code, "body": response.json()})
    return jsonify(results), 200

def verify_webhook(data, hmac_header):
    digest = hmac.new(
        SHOPIFY_API_SECRET.encode('utf-8'),
        data,
        hashlib.sha256
    ).digest()
    calculated_hmac = base64.b64encode(digest).decode()
    return hmac.compare_digest(calculated_hmac, hmac_header)

def is_in_smart_collection(product_id):
    url = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/collections/{SMART_COLLECTION_ID}/products.json"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        products = response.json().get("products", [])
        return any(str(prod.get("id")) == str(product_id) for prod in products)
    return False

def fetch_product(product_id):
    url = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}.json"
    response = requests.get(url, headers=HEADERS)
    return response.json().get("product") if response.status_code == 200 else None

def fetch_metafields(product_id):
    metafields_url = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}/metafields.json"
    meta_resp = requests.get(metafields_url, headers=HEADERS)
    return meta_resp.json().get("metafields", []) if meta_resp.status_code == 200 else []

def set_metafield(product_id, namespace, key, value_type, value):
    metafield_payload = {
        "metafield": {
            "namespace": namespace,
            "key": key,
            "type": value_type,
            "value": value
        }
    }
    url = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}/metafields.json"
    response = requests.post(url, headers=HEADERS, json=metafield_payload)
    print(f"📝 Set metafield {key} → {value} (status {response.status_code}): {response.text}")

def send_to_ab(product, ab_id=None):
    metafields = product.get("metafields", [])
    get_meta = lambda key: next((m['value'] for m in metafields if m['namespace'] == 'custom' and m['key'] == key), None)

    price = product.get("variants", [{}])[0].get("price")
    if not price and not DEFAULT_PRICE_RANGE_ID:
        print("❌ Missing price and no default price range ID")
        return

    ab_data = {
        "sShopProdName": product.get("title"),
        "sDescription": product.get("body_html"),
        "nShopProdCat_ID_1": get_meta("ab_category"),
        "nShopProdPeriod_ID": get_meta("ab_period"),
        "nNationality_ID": get_meta("ab_item_nationality")
    }

    if price:
        ab_data["nPrice"] = float(price)
    elif DEFAULT_PRICE_RANGE_ID:
        ab_data["nShopProdPriceRange_ID"] = int(DEFAULT_PRICE_RANGE_ID)

    image_url = product.get("image", {}).get("src")
    if image_url:
        ab_data["sImageURL_1"] = image_url

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    if ab_id:
        url = f"https://api.antiquesboutique.com/product/{ab_id}?sAPIKey={AB_API_KEY}"
    else:
        url = f"https://api.antiquesboutique.com/product/?sAPIKey={AB_API_KEY}"

    response = requests.post(url, headers=headers, data=ab_data)

    if response.status_code == 200:
        if not ab_id:
            result = response.json()
            ab_id = result.get("nShopProd_ID")
            if ab_id:
                set_metafield(product["id"], "custom", "ab_product_id", "single_line_text_field", str(ab_id))
                set_metafield(product["id"], "custom", "published_on_ab", "boolean", "true")

        product_hash = compute_product_hash(product)
        set_metafield(product["id"], "custom", "last_synced_hash", "single_line_text_field", product_hash)
    else:
        print(f"❌ AB API Error {response.status_code}: {response.text}")

@app.route("/webhook/products", methods=["POST"])
def handle_product_webhook():
    data = request.get_data()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256")

    if not verify_webhook(data, hmac_header):
        abort(401)

    payload = json.loads(data)
    topic = request.headers.get("X-Shopify-Topic")
    product_id = payload.get("id")

    if is_debounced(product_id):
        print("⏳ Debounced: recently handled.")
        return "Debounced", 200

    if topic == "products/create":
        time.sleep(3)
        full_product = fetch_product(product_id)
        metafields = fetch_metafields(product_id)
        full_product["metafields"] = metafields

        tags = full_product.get("tags", "").lower()
        status = full_product.get("status")
        variants = full_product.get("variants", [])
        inventory = sum([v.get("inventory_quantity", 0) for v in variants])

        ab_id_meta = next((m for m in metafields if m['namespace'] == 'custom' and m['key'] == 'ab_product_id'), None)
        published_flag = next((m for m in metafields if m['namespace'] == 'custom' and m['key'] == 'published_on_ab'), None)

        if ab_id_meta and ab_id_meta.get('value'):
            print("⛔️ Product already created on AB. Skipping.")
        elif status == "active" and "old" in tags and inventory > 0 and (not published_flag or published_flag.get("value") != "true"):
            print("✅ Creating new AB product...")
            send_to_ab(full_product)
        else:
            print("⛔️ Skipping create: Conditions not met.")

    elif topic == "products/update":
        full_product = fetch_product(product_id)
        metafields = fetch_metafields(product_id)
        full_product["metafields"] = metafields

        ab_id_meta = next((m for m in metafields if m['namespace'] == 'custom' and m['key'] == 'ab_product_id'), None)
        if not ab_id_meta or not ab_id_meta.get('value'):
            print("⛔️ Skipping update: No ab_product_id present")
            return "No AB ID", 200

        last_hash_meta = next((m for m in metafields if m['namespace'] == 'custom' and m['key'] == 'last_synced_hash'), None)
        last_saved_hash = last_hash_meta.get('value') if last_hash_meta else None
        current_hash = compute_product_hash(full_product)

        if current_hash == last_saved_hash:
            print("⏩ No changes detected. Skipping AB update.")
            return "No changes", 200

        if is_in_smart_collection(product_id):
            print("🔄 Updating AB product...")
            send_to_ab(full_product, ab_id=ab_id_meta["value"])
        else:
            print("⛔️ Skipping update: Product not in smart collection")

    return "Webhook processed", 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)
