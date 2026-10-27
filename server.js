require("dotenv").config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("JWT_SECRET is required");

const db = new Database(path.join(__dirname, "storeak.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  product_id TEXT NOT NULL,
  package_id TEXT NOT NULL,
  player_ref TEXT NOT NULL,
  amount_dzd INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'PAYMENT_PENDING',
  delivery_status TEXT NOT NULL DEFAULT 'BLOCKED_UNTIL_PAYMENT',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  provider TEXT NOT NULL,
  provider_ref TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_payment_provider_ref
ON payments(provider, provider_ref);
`);

const catalog = {
  freefire: {
    name: "Free Fire",
    field: "Player ID",
    packages: [
      ["ff100","100 Diamonds",259],["ff310","310 Diamonds",750],
      ["ff520","520 Diamonds",1190],["ff1060","1060 Diamonds",2290],
      ["ff2180","2180 Diamonds",4290]
    ]
  },
  pubg: {
    name: "PUBG Mobile",
    field: "Player ID",
    packages: [
      ["pubg60","60 UC",258],["pubg325","325 UC",1190],
      ["pubg660","660 UC",2290],["pubg1800","1800 UC",5790],
      ["pubg3850","3850 UC",10390]
    ]
  },
  efootball: {
    name: "eFootball",
    field: "Account ID",
    packages: [
      ["ef130","130 Coins",500],["ef550","550 Coins",1490],
      ["ef1040","1040 Coins",2490],["ef2130","2130 Coins",4990]
    ]
  },
  clash: {
    name: "Clash of Clans",
    field: "Player Tag",
    packages: [
      ["coc500","500 Gems",790],["coc1200","1200 Gems",1590],
      ["coc2500","2500 Gems",2990],["coc6500","6500 Gems",6990]
    ]
  },
  bloodstrike: {
    name: "Blood Strike",
    field: "Player ID",
    packages: [
      ["bs105","105 Gold",280],["bs320","320 Gold",750],
      ["bs540","540 Gold",1190],["bs1100","1100 Gold",2290],
      ["bs2260","2260 Gold",4290],["bs5800","5800 Gold",10390],
      ["bs_pass","Premium Pass",2000],["bs_elite","Elite Pass",990]
    ]
  },
  lol: {
    name: "League of Legends",
    field: "Riot ID",
    packages: [
      ["lol1250","1250 RP",2190],["lol2800","2800 RP",4300]
    ]
  },
  snapchat: {
    name: "Snapchat Plus",
    field: "Snapchat username/email",
    packages: [
      ["sc1","1 Month",2890],["sc3","3 Months",6990],
      ["sc6","6 Months",13900],["sc12","12 Months",28900]
    ]
  },
  youtube: {
    name: "YouTube Premium",
    field: "Google account email",
    packages: [
      ["yt1","1 Month",1200],["yt3","3 Months",3200],
      ["yt6","6 Months",5900],["yt12","12 Months",10900]
    ]
  }
};

function ensureAdmin() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return;
  const existing = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if (!existing) {
    const hash = bcrypt.hashSync(password, 12);
    db.prepare("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)")
      .run(email, hash, "admin");
    console.log(`Admin created: ${email}`);
  }
}
ensureAdmin();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || true }));
app.use(express.json({ limit: "100kb" }));
app.use(rateLimit({ windowMs: 60 * 1000, limit: 120 }));

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}
function adminOnly(req,res,next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}

app.get("/api/catalog", (req,res) => res.json(catalog));

app.get("/api/payment-info", (req,res) => {
  res.json({
    baridimob: {
      enabled: Boolean(process.env.BARIDIPAY_RIP),
      rip: process.env.BARIDIPAY_RIP || null
    },
    binancePay: { enabled: Boolean(process.env.BINANCE_API_KEY && process.env.BINANCE_API_SECRET) },
    redotpay: { enabled: Boolean(process.env.REDOTPAY_CHECKOUT_URL) }
  });
});

app.post("/api/register", async (req,res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8)
    return res.status(400).json({ error: "Valid email and password of at least 8 characters required" });
  try {
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare("INSERT INTO users(email,password_hash) VALUES(?,?)").run(email, hash);
    res.json({ id: info.lastInsertRowid });
  } catch {
    res.status(409).json({ error: "Email already registered" });
  }
});

app.post("/api/login", async (req,res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: "Invalid email or password" });
  const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:"7d" });
  res.json({ token, user:{id:user.id,email:user.email,role:user.role} });
});

app.post("/api/orders", auth, (req,res) => {
  const productId = String(req.body.productId || "");
  const packageId = String(req.body.packageId || "");
  const playerRef = String(req.body.playerRef || "").trim();
  const product = catalog[productId];
  if (!product) return res.status(400).json({ error:"Invalid product" });
  const pack = product.packages.find(x => x[0] === packageId);
  if (!pack) return res.status(400).json({ error:"Invalid package" });
  if (playerRef.length < 2 || playerRef.length > 120)
    return res.status(400).json({ error:"Invalid player/account reference" });

  const result = db.prepare(`
    INSERT INTO orders(user_id,product_id,package_id,player_ref,amount_dzd)
    VALUES(?,?,?,?,?)
  `).run(req.user.id, productId, packageId, playerRef, pack[2]);

  res.json({
    orderId: result.lastInsertRowid,
    amountDzd: pack[2],
    status:"PAYMENT_PENDING",
    deliveryStatus:"BLOCKED_UNTIL_PAYMENT"
  });
});

app.post("/api/orders/:id/payment", auth, (req,res) => {
  const orderId = Number(req.params.id);
  const provider = String(req.body.provider || "");
  const providerRef = String(req.body.providerRef || "").trim();
  const order = db.prepare("SELECT * FROM orders WHERE id=? AND user_id=?").get(orderId, req.user.id);
  if (!order) return res.status(404).json({ error:"Order not found" });
  if (!["BARIDIMOB","BINANCE_PAY","REDOTPAY"].includes(provider))
    return res.status(400).json({ error:"Unsupported provider" });
  if (provider === "BARIDIMOB" && !/^[A-Za-z0-9._-]{4,80}$/.test(providerRef))
    return res.status(400).json({ error:"Invalid payment reference" });

  try {
    db.prepare("INSERT INTO payments(order_id,provider,provider_ref) VALUES(?,?,?)")
      .run(orderId, provider, providerRef);
    res.json({ ok:true, status:"PENDING_VERIFICATION" });
  } catch {
    res.status(409).json({ error:"This transaction reference has already been submitted" });
  }
});

app.get("/api/my-orders", auth, (req,res) => {
  const rows = db.prepare(`
    SELECT o.*, p.provider, p.provider_ref, p.status AS payment_status
    FROM orders o LEFT JOIN payments p ON p.order_id=o.id
    WHERE o.user_id=? ORDER BY o.id DESC
  `).all(req.user.id);
  res.json(rows);
});

app.get("/api/admin/orders", auth, adminOnly, (req,res) => {
  res.json(db.prepare(`
    SELECT o.*, u.email, p.provider, p.provider_ref, p.status AS payment_status
    FROM orders o
    LEFT JOIN users u ON u.id=o.user_id
    LEFT JOIN payments p ON p.order_id=o.id
    ORDER BY o.id DESC
  `).all());
});

app.post("/api/admin/orders/:id/confirm-payment", auth, adminOnly, (req,res) => {
  const id = Number(req.params.id);
  const order = db.prepare("SELECT * FROM orders WHERE id=?").get(id);
  if (!order) return res.status(404).json({error:"Order not found"});
  db.prepare("UPDATE orders SET status='PAID', delivery_status='READY_FOR_DELIVERY' WHERE id=?").run(id);
  db.prepare("UPDATE payments SET status='CONFIRMED' WHERE order_id=?").run(id);
  res.json({ok:true});
});

app.post("/api/admin/orders/:id/mark-delivered", auth, adminOnly, (req,res) => {
  const id = Number(req.params.id);
  const order = db.prepare("SELECT * FROM orders WHERE id=?").get(id);
  if (!order) return res.status(404).json({error:"Order not found"});
  if (order.status !== "PAID") return res.status(400).json({error:"Payment must be confirmed first"});
  db.prepare("UPDATE orders SET delivery_status='DELIVERED' WHERE id=?").run(id);
  res.json({ok:true});
});

app.get("/api/payment-status", (req,res) => {
  res.json({
    baridimob: Boolean(process.env.BARIDIPAY_RIP),
    binancePay: Boolean(process.env.BINANCE_API_KEY && process.env.BINANCE_API_SECRET && process.env.BINANCE_MERCHANT_ID),
    redotpay: Boolean(process.env.REDOTPAY_CHECKOUT_URL),
    gameFulfillmentProvider: Boolean(process.env.GAME_PROVIDER_BASE_URL && process.env.GAME_PROVIDER_API_KEY)
  });
});

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT, () => {
  console.log(`STORE AK running at http://localhost:${PORT}`);
});
