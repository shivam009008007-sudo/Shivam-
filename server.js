require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "store.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','admin')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Daily Essentials',
  price REAL NOT NULL CHECK(price >= 0),
  stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
  emoji TEXT NOT NULL DEFAULT '🛍️',
  description TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  address TEXT NOT NULL,
  payment_method TEXT NOT NULL CHECK(payment_method IN ('COD','UPI')),
  items_json TEXT NOT NULL,
  total REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'New',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const initialProducts = [
  ["Aashirvaad Atta 5 kg","Atta, Rice & Dal",285,20,"🌾","Everyday whole wheat atta"],
  ["Fortune Sunflower Oil 1 L","Oil & Ghee",145,25,"🫗","Cooking oil for everyday meals"],
  ["Basmati Rice 1 kg","Atta, Rice & Dal",95,30,"🍚","Quality rice for home cooking"],
  ["Sugar 1 kg","Atta, Rice & Dal",48,40,"🧂","Daily kitchen essential"],
  ["Assorted Biscuits","Biscuits & Snacks",10,100,"🍪","Tea-time biscuits"],
  ["Namkeen Pack","Biscuits & Snacks",20,60,"🥨","Crunchy savoury snack"],
  ["Bath Soap","Personal Care",35,50,"🧼","Daily bathing soap"],
  ["Shampoo Sachet","Personal Care",2,200,"🧴","Convenient single-use sachet"],
  ["Washing Powder 1 kg","Home Care",90,35,"🫧","For everyday laundry"],
  ["LED Bulb 9W","Electronics & Other",75,15,"💡","Energy-saving LED bulb"]
];
const count = db.prepare("SELECT COUNT(*) AS n FROM products").get().n;
if (!count) {
  const insert = db.prepare("INSERT INTO products(name,category,price,stock,emoji,description) VALUES(?,?,?,?,?,?)");
  const tx = db.transaction(rows => rows.forEach(row => insert.run(...row)));
  tx(initialProducts);
}

async function seedAdmin() {
  const email = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || "";
  if (!email || !password || password === "ChangeThisToAStrongPassword123!") {
    console.warn("Admin not seeded: set ADMIN_EMAIL and a new strong ADMIN_PASSWORD in .env.");
    return;
  }
  const existing = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  const hash = await bcrypt.hash(password, 12);
  if (existing) {
    db.prepare("UPDATE users SET name=?, password_hash=?, role='admin' WHERE id=?")
      .run(process.env.ADMIN_NAME || "Store Admin", hash, existing.id);
  } else {
    db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
      .run(process.env.ADMIN_NAME || "Store Admin", email, hash);
  }
  console.log("Admin account is ready for:", email);
}
seedAdmin().catch(err => { console.error("Admin setup error", err); process.exit(1); });

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: dataDir }),
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));
app.get("/admin", (req, res) => res.sendFile(path.join(publicDir, "admin.html")));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please log in first." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(404).json({ error: "Not found." });
  }
  next();
}
function safeUser(user) {
  return { id: user.id, name: user.name, email: user.email, role: user.role };
}

app.get("/api/config", (req, res) => res.json({ whatsappNumber: String(process.env.WHATSAPP_NUMBER || "").replace(/\D/g, "") }));
app.get("/api/me", (req, res) => res.json({ user: req.session.user || null }));
app.post("/api/register", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (name.length < 2 || name.length > 80) return res.status(400).json({ error: "Please enter your name." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
  if (password.length > 72) return res.status(400).json({ error: "Password is too long." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'customer')")
      .run(name, email, hash);
    const user = db.prepare("SELECT id,name,email,role FROM users WHERE id=?").get(result.lastInsertRowid);
    req.session.user = safeUser(user);
    res.status(201).json({ user: req.session.user });
  } catch (e) {
    if (String(e.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "This email is already registered." });
    res.status(500).json({ error: "Could not create account." });
  }
});
app.post("/api/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Email or password is incorrect." });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start session." });
    req.session.user = safeUser(user);
    res.json({ user: req.session.user });
  });
});
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

app.get("/api/products", (req, res) => {
  const products = db.prepare("SELECT id,name,category,price,stock,emoji,description FROM products WHERE active=1 ORDER BY id DESC").all();
  res.json({ products });
});
app.get("/api/my-orders", requireLogin, (req, res) => {
  const orders = db.prepare("SELECT id,customer_name,phone,address,payment_method,items_json,total,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC")
    .all(req.session.user.id).map(o => ({...o, items: JSON.parse(o.items_json)}));
  res.json({ orders });
});
app.post("/api/orders", requireLogin, (req, res) => {
  const customerName = String(req.body.customerName || "").trim();
  const phone = String(req.body.phone || "").trim();
  const address = String(req.body.address || "").trim();
  const paymentMethod = req.body.paymentMethod === "UPI" ? "UPI" : "COD";
  const incoming = Array.isArray(req.body.items) ? req.body.items : [];
  if (customerName.length < 2 || !/^[0-9+\-\s]{10,16}$/.test(phone) || address.length < 8) {
    return res.status(400).json({ error: "Please enter a valid name, phone number and complete delivery address." });
  }
  if (!incoming.length || incoming.length > 50) return res.status(400).json({ error: "Your cart is empty or has too many items." });
  const getProduct = db.prepare("SELECT id,name,price,stock,active,emoji FROM products WHERE id=?");
  const changeStock = db.prepare("UPDATE products SET stock=stock-? WHERE id=? AND stock>=?");
  const insertOrder = db.prepare("INSERT INTO orders(user_id,customer_name,phone,address,payment_method,items_json,total) VALUES(?,?,?,?,?,?,?)");
  try {
    const result = db.transaction(() => {
      const items = [];
      let total = 0;
      for (const line of incoming) {
        const id = Number(line.id), qty = Number(line.qty);
        if (!Number.isInteger(id) || !Number.isInteger(qty) || qty < 1 || qty > 99) throw new Error("Invalid item quantity.");
        const p = getProduct.get(id);
        if (!p || !p.active) throw new Error("A product is no longer available.");
        if (p.stock < qty) throw new Error(`${p.name}: only ${p.stock} left in stock.`);
        items.push({id:p.id,name:p.name,price:p.price,qty,emoji:p.emoji});
        total += p.price * qty;
      }
      for (const item of items) {
        if (changeStock.run(item.qty, item.id, item.qty).changes !== 1) throw new Error("Stock changed. Please try again.");
      }
      const order = insertOrder.run(req.session.user.id, customerName, phone, address, paymentMethod, JSON.stringify(items), total);
      return { id: Number(order.lastInsertRowid), total };
    })();
    res.status(201).json({ order: result });
  } catch (e) {
    res.status(400).json({ error: e.message || "Could not place order." });
  }
});

// Admin APIs are role-protected on the server; hiding a link alone is not security.
app.get("/api/admin/summary", requireAdmin, (req, res) => {
  res.json({
    products: db.prepare("SELECT COUNT(*) AS n FROM products").get().n,
    activeProducts: db.prepare("SELECT COUNT(*) AS n FROM products WHERE active=1").get().n,
    orders: db.prepare("SELECT COUNT(*) AS n FROM orders").get().n,
    pending: db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status='New'").get().n,
    sales: db.prepare("SELECT COALESCE(SUM(total),0) AS n FROM orders WHERE status!='Cancelled'").get().n
  });
});
app.get("/api/admin/products", requireAdmin, (req, res) => {
  res.json({ products: db.prepare("SELECT * FROM products ORDER BY id DESC").all() });
});
app.post("/api/admin/products", requireAdmin, (req, res) => {
  const p = validateProduct(req.body);
  if (p.error) return res.status(400).json({error:p.error});
  const r = db.prepare("INSERT INTO products(name,category,price,stock,emoji,description,active) VALUES(?,?,?,?,?,?,?)")
    .run(p.name,p.category,p.price,p.stock,p.emoji,p.description,p.active);
  res.status(201).json({id:Number(r.lastInsertRowid)});
});
app.put("/api/admin/products/:id", requireAdmin, (req, res) => {
  const p = validateProduct(req.body);
  if (p.error) return res.status(400).json({error:p.error});
  const r = db.prepare("UPDATE products SET name=?,category=?,price=?,stock=?,emoji=?,description=?,active=? WHERE id=?")
    .run(p.name,p.category,p.price,p.stock,p.emoji,p.description,p.active,Number(req.params.id));
  if (!r.changes) return res.status(404).json({error:"Product not found."});
  res.json({ok:true});
});
app.delete("/api/admin/products/:id", requireAdmin, (req, res) => {
  const r = db.prepare("UPDATE products SET active=0 WHERE id=?").run(Number(req.params.id));
  if (!r.changes) return res.status(404).json({error:"Product not found."});
  res.json({ok:true});
});
app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const orders = db.prepare("SELECT * FROM orders ORDER BY id DESC").all()
    .map(o => ({...o, items:JSON.parse(o.items_json)}));
  res.json({orders});
});
app.patch("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const allowed = ["New","Confirmed","Packed","Out for delivery","Delivered","Cancelled"];
  if (!allowed.includes(req.body.status)) return res.status(400).json({error:"Invalid order status."});
  const r = db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status, Number(req.params.id));
  if (!r.changes) return res.status(404).json({error:"Order not found."});
  res.json({ok:true});
});
function validateProduct(body) {
  const name=String(body.name||"").trim(), category=String(body.category||"Daily Essentials").trim();
  const price=Number(body.price), stock=Number(body.stock);
  const emoji=String(body.emoji||"🛍️").slice(0,8), description=String(body.description||"").trim();
  const active=body.active === false || body.active === 0 || body.active === "0" ? 0 : 1;
  if (!name || name.length>120 || !category || category.length>80) return {error:"Enter a product name and category."};
  if (!Number.isFinite(price)||price<0||price>10000000) return {error:"Enter a valid price."};
  if (!Number.isInteger(stock)||stock<0||stock>10000000) return {error:"Enter valid stock quantity."};
  return {name,category,price,stock,emoji,description,active};
}

app.get("*", (req, res) => res.sendFile(path.join(publicDir, "index.html")));
app.listen(PORT, () => console.log(`Shivam FMCG Store running at http://localhost:${PORT}`));
