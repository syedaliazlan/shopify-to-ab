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

SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
SHOPIFY_STORE_DOMAIN = os.getenv("SHOPIFY_STORE_DOMAIN")
SHOPIFY_ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN")
AB_API_KEY = os.getenv("AB_API_KEY")
DEFAULT_PRICE_RANGE_ID = os.getenv("DEFAULT_PRICE_RANGE_ID")

SHOPIFY_API_VERSION = "2023-10"
HEADERS = {
    "Content-Type": "application/json",
    "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
}
REST_BASE = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"

SMART_COLLECTION_ID = "676440899969"
recently_handled = {}

def is_debounced(pid):
    now = time.time()
    if pid in recently_handled and now - recently_handled[pid] < 15:
        return True
    recently_handled[pid] = now
    return False

def compute_product_hash(prod):
    mf = prod.get("metafields", [])
    getm = lambda k: next((m['value'] for m in mf if m['namespace']=='custom' and m['key']==k), "")
    rd = {
        "title": prod.get("title",""),
        "body_html": prod.get("body_html",""),
        "price": prod.get("variants",[{}])[0].get("price",""),
        "image": prod.get("image",{}).get("src",""),
        "ab_category": getm("ab_category"),
        "ab_period": getm("ab_period"),
        "ab_item_nationality": getm("ab_item_nationality")
    }
    return hashlib.sha256(json.dumps(rd, sort_keys=True).encode()).hexdigest()

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
    if not price and not DEFAULT_PRICE_RANGE_ID:
        print("❌ Missing price")
        return
    d = {
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
    img = prod.get("image",{}).get("src")
    if img: d["sImageURL_1"] = img

    r = requests.post(
        f"https://api.antiquesboutique.com/product/{ab_id or ''}?sAPIKey={AB_API_KEY}",
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        data=d
    )
    if r.status_code == 200:
        if not ab_id:
            new = r.json().get("nShopProd_ID")
            if new:
                # ab_product_id (string)
                requests.post(
                    f"{REST_BASE}/products/{prod['id']}/metafields.json",
                    headers=HEADERS,
                    json={
                        "metafield": {
                            "namespace": "custom",
                            "key": "ab_product_id",
                            "type": "single_line_text_field",
                            "value": str(new)
                        }
                    }
                )
                # published_on_ab (boolean)
                requests.post(
                    f"{REST_BASE}/products/{prod['id']}/metafields.json",
                    headers=HEADERS,
                    json={
                        "metafield": {
                            "namespace": "custom",
                            "key": "published_on_ab",
                            "type": "boolean",
                            "value": "true"
                        }
                    }
                )
        # always update hash
        h = compute_product_hash(prod)
        requests.post(
            f"{REST_BASE}/products/{prod['id']}/metafields.json",
            headers=HEADERS,
            json={
                "metafield": {
                    "namespace": "custom",
                    "key": "last_synced_hash",
                    "type": "single_line_text_field",
                    "value": h
                }
            }
        )
    else:
        print("❌ AB sync error:", r.text)

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

        # recreate if valid again
        if not abmf.get("value") and status=="active" and "old" in tags and inv>0:
            print("🔁 Recreating product on AB")
            send_to_ab(prod)
            return "Recreated on AB", 200

        # update logic
        last = next((m["value"] for m in prod["metafields"] if m["namespace"]=="custom" and m["key"]=="last_synced_hash"), None)
        new_hash = compute_product_hash(prod)
        if new_hash != last and abmf.get("value") and "old" in tags and status=="active" and inv>0:
            print("🔄 Updating AB product")
            send_to_ab(prod, ab_id=abmf["value"])
        else:
            print("⛔️ No AB update or sync needed")

    return "Webhook processed", 200

if __name__ == "__main__":
    app.run()
