# Shopify to Antiques Boutique (AB) Product Sync

This Flask-based Python application automates the process of synchronizing products from a Shopify store to the Antiques Boutique (AB) platform. It handles product creation, updates, and deletions based on specific business logic using Shopify webhooks and the AB API.

---

## 🚀 Features

* ✅ Sync newly created Shopify products to AB if they meet specific criteria
* 🔄 Update existing AB products when Shopify data changes
* 🗑️ Delete AB products when they are no longer valid (e.g., draft, zero inventory, or removed "old" tag)
* 🔁 Recreate deleted AB products if they become eligible again
* 🧠 Prevent redundant updates using content hashing
* 🔒 Verifies Shopify webhooks with HMAC signature
* 🧹 Automatically cleans up related metafields when products are deleted from AB

---

## 🧱 Tech Stack

* **Backend**: Python, Flask
* **Platform**: Shopify Admin API (REST + Webhooks)
* **Third Party API**: Antiques Boutique (AB) Product API
* **Deployment**: Render.com (or any Flask-compatible server)

---

## ⚙️ Environment Variables

Create a `.env` file and add the following:

```env
SHOPIFY_API_SECRET=your_shopify_shared_secret
SHOPIFY_STORE_DOMAIN=your-store.myshopify.com
SHOPIFY_ACCESS_TOKEN=your_private_app_token
AB_API_KEY=your_ab_api_key
DEFAULT_PRICE_RANGE_ID=optional_default_price_range_id
WEBHOOK_CALLBACK_URL=https://your-app-url.onrender.com
```

---

## 🧩 How It Works

### 1. Webhook Registration

Register the required webhooks by visiting:

```
GET /register_webhook
```

This sets up Shopify webhooks for:

* `products/create`
* `products/update`

Webhook callbacks will be received at:

```
/webhook/products
```

### 2. Product Create Logic

When a product is created in Shopify, the app checks:

* Product `status == "active"`
* Tag contains `"old"`
* Inventory > 0
* Not already synced (no `published_on_ab` metafield)

If all conditions are met, the product is posted to AB and the following metafields are added:

* `custom.ab_product_id` (string)
* `custom.published_on_ab` (boolean)
* `custom.last_synced_hash` (hash of synced content)

### 3. Product Update Logic

Triggered when:

* Product content changes (via hash comparison)
* Product is still active, has tag "old", and inventory > 0

AB product is updated using its stored `ab_product_id`.

### 4. Product Deletion from AB

Triggers when:

* "old" tag is removed
* Product is changed to `draft`
* Inventory is set to 0 or less

Conditions:

* The product must have a valid `ab_product_id`
* It is checked first via AB GET API

If confirmed, the product is deleted from AB and all related metafields (`ab_product_id`, `published_on_ab`, `last_synced_hash`) are removed from Shopify.

### 5. Product Recreation

If a product was previously deleted but becomes eligible again (active, has "old", inventory > 0), it will be recreated on AB automatically.

---

## 🔍 Key Fields Mapped to AB API

| AB Field             | Shopify Source                        |
| -------------------- | ------------------------------------- |
| `sRef`               | SKU from first product variant        |
| `sShopProdName`      | Product title                         |
| `sDescription`       | Product body (HTML)                   |
| `sImageURL_1`        | Main product image URL                |
| `nPrice`             | Price from first variant              |
| `nShopProdCat_ID_1`  | From metafield: `ab_category`         |
| `nShopProdPeriod_ID` | From metafield: `ab_period`           |
| `nNationality_ID`    | From metafield: `ab_item_nationality` |

---

## 🖥️ Deployment Notes (Render)

Make sure Flask listens on the correct host and port:

```python
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
```

Also, make sure to update your `.env` file on Render and re-register webhooks after every deployment or base URL change.

---

## 📦 Optional Improvements

* Add logging to a persistent store
* Build a UI dashboard to view sync status
* Add support for bulk product imports
* Retry failed AB syncs via background task queue (e.g., Celery + Redis)

---

## 📬 Support

For issues or feature requests, please open an issue on the GitHub repo.

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

Made with ❤️ by Ali
