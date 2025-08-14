import os
import sys
import hmac
import hashlib
import base64
import json
import time
import threading
import queue
from flask import Flask, request, abort, jsonify
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# ── logging helper ─────────────────────────────────────────────────────────────
def log(*args):
    print(*args, flush=True)

# ── ENV ────────────────────────────────────────────────────────────────────────
SHOPIFY_API_SECRET     = os.getenv("SHOPIFY_API_SECRET")
SHOPIFY_STORE_DOMAIN   = os.getenv("SHOPIFY_STORE_DOMAIN")                      # admin domain
SHOPIFY_PUBLIC_DOMAIN  = os.getenv("SHOPIFY_PUBLIC_DOMAIN", SHOPIFY_STORE_DOMAIN)  # public storefront domain
SHOPIFY_ACCESS_TOKEN   = os.getenv("SHOPIFY_ACCESS_TOKEN")
AB_API_KEY             = os.getenv("AB_API_KEY")
DEFAULT_PRICE_RANGE_ID = os.getenv("DEFAULT_PRICE_RANGE_ID")
WEBHOOK_CALLBACK_URL   = (os.getenv("WEBHOOK_CALLBACK_URL") or "").rstrip("/")  # normalize

SHOPIFY_API_VERSION = "2023-10"
HEADERS = {
    "Content-Type": "application/json",
    "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
}
REST_BASE = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"

# ── HTTP session with retries/timeouts ─────────────────────────────────────────
SESSION = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods={"GET", "POST", "DELETE"},
)
SESSION.mount("https://", HTTPAdapter(max_retries=retries))
SESSION.mount("http://",  HTTPAdapter(max_retries=retries))
DEFAULT_TIMEOUT = (5, 25)  # (connect, read)

# ── State / debounce ───────────────────────────────────────────────────────────
DEBOUNCE_WINDOW = 30  # seconds
recently_handled = {}  # (pid:topic) -> ts

def is_debounced(pid, topic):
    key = f"{pid}:{topic}"
    now = time.time()
    ts = recently_handled.get(key)
    if ts is not None and now - ts < DEBOUNCE_WINDOW:
        return True
    recently_handled[key] = now
    return False

# ── Async worker infra ─────────────────────────────────────────────────────────
task_q: queue.Queue = queue.Queue(maxsize=1000)
_worker_started = False
_worker_lock = threading.Lock()

def worker_loop():
    log("👷 worker loop running")
    while True:
        try:
            task = task_q.get()  # blocks
            if task is None:
                task_q.task_done()
                break
            handle_product_task(**task)
        except Exception as e:
            log("❌ worker error:", repr(e))
        finally:
            try:
                task_q.task_done()
            except Exception:
                pass

def start_worker_if_needed():
    """Start the background worker once per process; safe to call many times."""
    global _worker_started
    if _worker_started:
        return
    with _worker_lock:
        if _worker_started:
            return
        t = threading.Thread(target=worker_loop, daemon=True)
        t.start()
        _worker_started = True
        log("✅ background worker started in this process")

# Works on all Flask versions
@app.before_request
def _ensure_worker():
    start_worker_if_needed()

# ── Shopify helpers ────────────────────────────────────────────────────────────
def fetch_product(pid):
    r = SESSION.get(f"{REST_BASE}/products/{pid}.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT)
    return r.json().get("product")

def fetch_metafields(pid):
    r = SESSION.get(f"{REST_BASE}/products/{pid}/metafields.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT)
    return r.json().get("metafields", [])

def create_metafield(pid, namespace, key, type_, value):
    return SESSION.post(
        f"{REST_BASE}/products/{pid}/metafields.json",
        headers=HEADERS,
        json={"metafield": {"namespace": namespace, "key": key, "type": type_, "value": value}},
        timeout=DEFAULT_TIMEOUT
    )

def get_metafield_value(metafields, namespace, key, default=None):
    for m in metafields:
        if m.get("namespace") == namespace and m.get("key") == key:
            return m.get("value")
    return default

def delete_metafield(pid, mf_id):
    SESSION.delete(f"{REST_BASE}/products/{pid}/metafields/{mf_id}.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT)

def clear_ab_metafields(pid):
    for mf in fetch_metafields(pid):
        if mf['namespace'] == "custom" and mf['key'] in {"ab_product_id", "published_on_ab", "last_synced_hash", "ab_sync_status"}:
            delete_metafield(pid, mf['id'])

# ── AB helpers ─────────────────────────────────────────────────────────────────
def check_ab_product_exists(ab_id):
    r = SESSION.get(f"https://api.antiquesboutique.com/product/{ab_id}?sAPIKey={AB_API_KEY}", timeout=DEFAULT_TIMEOUT)
    return r.status_code == 200 and r.json().get("status") == "success"

def delete_ab_product(ab_id):
    r = SESSION.delete(f"https://api.antiquesboutique.com/product/{ab_id}?sAPIKey={AB_API_KEY}", timeout=DEFAULT_TIMEOUT)
    log("🗑️ Deleted AB product" if r.status_code == 200 else f"❌ AB delete failed {r.status_code}")

# ── Update detection ───────────────────────────────────────────────────────────
def compute_product_hash(prod):
    mf = prod.get("metafields", [])
    getm = lambda k: get_metafield_value(mf, "custom", k, "")
    images = [img.get("src", "") for img in (prod.get("images") or [])][:20]
    if not images:
        main = prod.get("image", {}).get("src", "")
        images = [main] if main else []
    rd = {
        "title": prod.get("title", ""),
        "body_html": prod.get("body_html", ""),
        "price": prod.get("variants", [{}])[0].get("price", ""),
        "images": images,
        "handle": prod.get("handle", ""),
        "ab_category": getm("ab_category"),
        "ab_period": getm("ab_period"),
        "ab_item_nationality": getm("ab_item_nationality"),
    }
    return hashlib.sha256(json.dumps(rd, sort_keys=True).encode()).hexdigest()

# ── Core: send to AB ───────────────────────────────────────────────────────────
def send_to_ab(prod, ab_id=None):
    mf = prod.get("metafields", [])
    getm = lambda k: get_metafield_value(mf, "custom", k, None)
    price = prod.get("variants", [{}])[0].get("price")
    sku   = prod.get("variants", [{}])[0].get("sku")

    if not price and not DEFAULT_PRICE_RANGE_ID:
        log("❌ Missing price and no DEFAULT_PRICE_RANGE_ID")
        return None

    d = {
        "sRef": sku,
        "sShopProdName": prod["title"],
        "sDescription": prod["body_html"],
        "nShopProdCat_ID_1": getm("ab_category"),
        "nShopProdPeriod_ID": getm("ab_period"),
        "nNationality_ID": getm("ab_item_nationality"),
    }
    if price:
        d["nPrice"] = float(price)
    else:
        d["nShopProdPriceRange_ID"] = int(DEFAULT_PRICE_RANGE_ID)

    # Images: up to 20
    gallery = [img.get("src", "") for img in (prod.get("images") or []) if img.get("src")]
    if not gallery:
        main = prod.get("image", {}).get("src")
        if main:
            gallery = [main]
    for idx, url in enumerate(gallery[:20], start=1):
        d[f"sImageURL_{idx}"] = url

    # External URL — PUBLIC domain
    handle = prod.get("handle")
    if handle:
        d["sExternalURL"] = f"https://{SHOPIFY_PUBLIC_DOMAIN}/products/{handle}"

    r = SESSION.post(
        f"https://api.antiquesboutique.com/product/{ab_id or ''}?sAPIKey={AB_API_KEY}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=d,
        timeout=DEFAULT_TIMEOUT
    )
    if r.status_code != 200:
        log("❌ AB sync error:", r.text)
        return None
    return r.json()

# ── Worker task (off-thread) ───────────────────────────────────────────────────
def handle_product_task(pid, topic):
    prod = fetch_product(pid)
    if not prod:
        log(f"⚠️ Product {pid} not found")
        return
    prod["metafields"] = fetch_metafields(pid)

    tags = (prod.get("tags") or "").lower()
    status = prod.get("status")
    inv = sum(v.get("inventory_quantity", 0) for v in prod.get("variants", []))

    ab_id = get_metafield_value(prod["metafields"], "custom", "ab_product_id")
    pub   = get_metafield_value(prod["metafields"], "custom", "published_on_ab")
    lock  = get_metafield_value(prod["metafields"], "custom", "ab_sync_status")

    if topic == "products/create":
        time.sleep(2)  # let Shopify finish writing images, etc.
        if ab_id:
            log("⛔️ Already on AB")
            return
        if lock == "creating":
            log("⏳ Create in progress — skip")
            return
        if not (status == "active" and "old" in tags and inv > 0 and (not pub or pub != "true")):
            log("⛔️ Create criteria not met")
            return

        log("✅ Creating on AB")
        create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "creating")
        try:
            resp = send_to_ab(prod)
            if resp and resp.get("nShopProd_ID"):
                create_metafield(pid, "custom", "ab_product_id", "single_line_text_field", str(resp["nShopProd_ID"]))
                create_metafield(pid, "custom", "published_on_ab", "boolean", "true")
                h = compute_product_hash(prod)
                create_metafield(pid, "custom", "last_synced_hash", "single_line_text_field", h)
                log(f"✅ AB created nShopProd_ID={resp['nShopProd_ID']}")
            else:
                log("⚠️ AB did not return nShopProd_ID")
        finally:
            create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "")

    else:  # products/update
        # deletion rules
        if ab_id and ("old" not in tags or status == "draft" or inv <= 0):
            if check_ab_product_exists(ab_id):
                delete_ab_product(ab_id)
            clear_ab_metafields(pid)
            log("🗑️ Deleted from AB due to rules")
            return

        if lock == "creating":
            log("⏳ Create in progress — skip update/recreate")
            return

        if not ab_id and status == "active" and "old" in tags and inv > 0:
            log("🔁 Recreating on AB")
            create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "creating")
            try:
                resp = send_to_ab(prod)
                if resp and resp.get("nShopProd_ID"):
                    create_metafield(pid, "custom", "ab_product_id", "single_line_text_field", str(resp["nShopProd_ID"]))
                    create_metafield(pid, "custom", "published_on_ab", "boolean", "true")
                    h = compute_product_hash(prod)
                    create_metafield(pid, "custom", "last_synced_hash", "single_line_text_field", h)
                    log(f"✅ AB re-created nShopProd_ID={resp['nShopProd_ID']}")
            finally:
                create_metafield(pid, "custom", "ab_sync_status", "single_line_text_field", "")
            return

        # normal update
        last = get_metafield_value(prod["metafields"], "custom", "last_synced_hash")
        new_hash = compute_product_hash(prod)
        if new_hash != last and ab_id and "old" in tags and status == "active" and inv > 0:
            log("🔄 Updating AB product")
            resp = send_to_ab(prod, ab_id=ab_id)
            if resp:
                create_metafield(pid, "custom", "last_synced_hash", "single_line_text_field", new_hash)
                log("✅ AB updated & hash refreshed")
        else:
            log("⛔️ No AB update or sync needed")

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return "OK", 200

@app.route("/diag", methods=["GET"])
def diag():
    return jsonify({
        "worker_started": _ensure_worker is not None and _worker_started,
        "queue_size": task_q.qsize(),
    }), 200

@app.route("/register_webhook", methods=["GET"])
def register_webhook():
    topics = ["products/create", "products/update"]
    results = []
    existing = SESSION.get(f"{REST_BASE}/webhooks.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT).json().get("webhooks", [])
    for topic in topics:
        addr = f"{WEBHOOK_CALLBACK_URL}/webhook/products"
        if any(w["topic"] == topic and w["address"] == addr for w in existing):
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
    for topic in ("products/create", "products/update"):
        matches = [w for w in webhooks if w["topic"] == topic and w["address"] == addr]
        report[topic] = [{"id": w["id"], "address": w["address"]} for w in matches]
        if fix and len(matches) > 1:
            keep = max(matches, key=lambda w: w["created_at"])
            for w in matches:
                if w["id"] != keep["id"]:
                    SESSION.delete(f"{REST_BASE}/webhooks/{w['id']}.json", headers=HEADERS, timeout=DEFAULT_TIMEOUT)
    return jsonify({"fixed": fix, "report": report}), 200

@app.route("/webhook/products", methods=["POST"])
def enqueue_webhook():
    raw = request.get_data()
    digest = hmac.new(SHOPIFY_API_SECRET.encode(), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(base64.b64encode(digest).decode(), request.headers.get("X-Shopify-Hmac-Sha256", "")):
        abort(401)

    payload = json.loads(raw)
    pid = payload.get("id")
    topic = request.headers.get("X-Shopify-Topic", "")

    # Ensure worker is started in this process (works even without any GETs)
    start_worker_if_needed()

    # Debounce & enqueue
    if not is_debounced(pid, topic):
        try:
            task_q.put_nowait({"pid": pid, "topic": topic})
            log(f"📥 queued task pid={pid} topic={topic}")
        except queue.Full:
            log("⚠️ Task queue full; dropping event")
    else:
        log(f"⏱️ debounced pid={pid} topic={topic}")

    return "Queued", 200

# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run()
