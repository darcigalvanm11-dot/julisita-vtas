const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 10000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "JULISITA2026";

const DATA_DIR = path.join(__dirname, "data");
const ORDERS_FILE = path.join(DATA_DIR, "orders.json");
const USERS_FILE = path.join(DATA_DIR, "users.json");

function ensureFile(file, initial) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, initial, "utf8");
  }
}

fs.mkdirSync(DATA_DIR, { recursive: true });
ensureFile(ORDERS_FILE, "[]");
ensureFile(USERS_FILE, "[]");

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

const PRODUCTS = [
  { id: "U110", type: "Única por ID", diamonds: "110", price: 3800 },
  { id: "U342", type: "Única por ID", diamonds: "342", price: 10200 },
  { id: "U572", type: "Única por ID", diamonds: "572", price: 15400 },
  { id: "U1166", type: "Única por ID", diamonds: "1.166", price: 28000 },
  { id: "U2398", type: "Única por ID", diamonds: "2.398", price: 55600 },
  { id: "U6160", type: "Única por ID", diamonds: "6.160", price: 137500 },
  { id: "I110", type: "Ilimitada", diamonds: "110", price: 4000 },
  { id: "I342", type: "Ilimitada", diamonds: "342", price: 11000 },
  { id: "I572", type: "Ilimitada", diamonds: "572", price: 17000 },
  { id: "I1166", type: "Ilimitada", diamonds: "1.166", price: 32000 },
  { id: "I2398", type: "Ilimitada", diamonds: "2.398", price: 64000 },
  { id: "I6160", type: "Ilimitada", diamonds: "6.160", price: 158000 }
];

function readArray(file) {
  try {
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    return Array.isArray(value) ? value : [];
  } catch (error) {
    console.error("No se pudo leer", file, error.message);
    return [];
  }
}

function writeArray(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2), "utf8");
}

function readOrders() {
  return readArray(ORDERS_FILE);
}

function writeOrders(value) {
  writeArray(ORDERS_FILE, value);
}

function readUsers() {
  return readArray(USERS_FILE);
}

function writeUsers(value) {
  writeArray(USERS_FILE, value);
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 120000, 64, "sha512").toString("hex");
}

function makePassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt: salt, hash: hashPassword(password, salt) };
}

function checkPassword(password, user) {
  const a = Buffer.from(hashPassword(password, user.salt), "hex");
  const b = Buffer.from(user.passwordHash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function makeUserToken(userId) {
  const secret = process.env.SESSION_SECRET || "JULISITA-SESSION-2026";
  return crypto.createHmac("sha256", secret).update(String(userId)).digest("hex");
}

function makeAdminToken() {
  return crypto.createHash("sha256").update("julista-admin:" + ADMIN_PASSWORD).digest("hex");
}

function getUser(req) {
  const header = String(req.headers.authorization || "");
  if (!header.startsWith("Bearer ")) return null;

  const token = header.slice(7).trim();
  if (!token) return null;

  const users = readUsers();

  for (const user of users) {
    const expected = makeUserToken(user.id);
    if (
      token.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))
    ) {
      return user;
    }
  }

  return null;
}

function requireUser(req, res, next) {
  const user = getUser(req);

  if (!user) {
    return res.status(401).json({ error: "Debes iniciar sesión." });
  }

  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const header = String(req.headers.authorization || "");

  if (header !== "Bearer " + makeAdminToken()) {
    return res.status(401).json({ error: "Sesión de administradora no válida." });
  }

  next();
}

function cleanOldOrders() {
  const ninetyDays = 90 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  const orders = readOrders();

  const kept = orders.filter(function (order) {
    const created = new Date(order.createdAt).getTime();
    if (!Number.isFinite(created)) return true;
    return now - created < ninetyDays;
  });

  if (kept.length !== orders.length) {
    writeOrders(kept);
  }
}

app.get("/api/products", function (req, res) {
  res.json(PRODUCTS);
});

app.post("/api/auth/register", function (req, res) {
  const name = String((req.body && req.body.name) || "").trim();
  const email = String((req.body && req.body.email) || "").trim().toLowerCase();
  const password = String((req.body && req.body.password) || "");

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Completa nombre, correo y contraseña." });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Introduce un correo válido." });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres." });
  }

  const users = readUsers();

  if (users.some(function (user) { return user.email === email; })) {
    return res.status(409).json({ error: "Ya existe una cuenta con ese correo." });
  }

  const secured = makePassword(password);

  const user = {
    id: "USR-" + crypto.randomBytes(6).toString("hex").toUpperCase(),
    name: name.slice(0, 100),
    email: email.slice(0, 150),
    passwordHash: secured.hash,
    salt: secured.salt,
    createdAt: new Date().toISOString()
  };

  users.push(user);
  writeUsers(users);

  res.status(201).json({
    user: { id: user.id, name: user.name, email: user.email },
    token: makeUserToken(user.id)
  });
});

app.post("/api/auth/login", function (req, res) {
  const email = String((req.body && req.body.email) || "").trim().toLowerCase();
  const password = String((req.body && req.body.password) || "");

  const user = readUsers().find(function (item) {
    return item.email === email;
  });

  if (!user || !checkPassword(password, user)) {
    return res.status(401).json({ error: "Correo o contraseña incorrectos." });
  }

  res.json({
    user: { id: user.id, name: user.name, email: user.email },
    token: makeUserToken(user.id)
  });
});

app.get("/api/auth/me", requireUser, function (req, res) {
  res.json({
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      createdAt: req.user.createdAt
    }
  });
});

app.get("/api/my/orders", requireUser, function (req, res) {
  cleanOldOrders();

  const orders = readOrders()
    .filter(function (order) {
      return order.userId === req.user.id;
    })
    .sort(function (a, b) {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

  res.json(orders);
});

app.post("/api/orders", requireUser, function (req, res) {
  const body = req.body || {};
  const customer = String(body.customer || req.user.name || "").trim();
  const playerId = String(body.playerId || "").trim();
  const region = String(body.region || "").trim();
  const itemsIn = Array.isArray(body.items) ? body.items : [];

  if (!customer || !playerId || !region || !itemsIn.length) {
    return res.status(400).json({
      error: "Completa nombre, ID, región y agrega productos."
    });
  }

  const items = [];

  for (const raw of itemsIn) {
    const product = PRODUCTS.find(function (item) {
      return item.id === raw.productId;
    });

    const qty = Math.max(1, Math.min(99, parseInt(raw.qty, 10) || 1));

    if (!product) {
      return res.status(400).json({ error: "Uno de los productos no existe." });
    }

    items.push({
      id: product.id,
      type: product.type,
      diamonds: product.diamonds,
      price: product.price,
      qty: qty
    });
  }

  const total = items.reduce(function (sum, item) {
    return sum + item.price * item.qty;
  }, 0);

  const now = new Date().toISOString();

  const order = {
    id: "JV-" + Date.now().toString().slice(-8),
    userId: req.user.id,
    customer: customer.slice(0, 100),
    playerId: playerId.slice(0, 80),
    region: region.slice(0, 40),
    notes: String(body.notes || "").trim().slice(0, 500),
    paymentMethod: String(body.paymentMethod || "").slice(0, 40),
    paymentReference: String(body.paymentReference || "").slice(0, 100),
    items: items,
    total: total,
    status: "PENDIENTE",
    createdAt: now,
    updatedAt: now
  };

  const orders = readOrders();
  orders.push(order);
  writeOrders(orders);

  res.status(201).json({
    id: order.id,
    total: order.total,
    status: order.status,
    createdAt: order.createdAt
  });
});

app.get("/api/my/orders/:id", requireUser, function (req, res) {
  const id = String(req.params.id || "").trim().toUpperCase();

  const order = readOrders().find(function (item) {
    return String(item.id).toUpperCase() === id && item.userId === req.user.id;
  });

  if (!order) {
    return res.status(404).json({
      error: "No encontramos ese pedido en tu cuenta."
    });
  }

  res.json(order);
});

app.post("/api/admin/login", function (req, res) {
  const password = String((req.body && req.body.password) || "");

  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Contraseña incorrecta." });
  }

  res.json({ token: makeAdminToken() });
});

app.get("/api/admin/orders", requireAdmin, function (req, res) {
  cleanOldOrders();

  const q = String(req.query.q || "").trim().toLowerCase();

  let orders = readOrders().sort(function (a, b) {
    return new Date(b.createdAt) - new Date(a.createdAt);
  });

  if (q) {
    orders = orders.filter(function (order) {
      return [
        order.id,
        order.customer,
        order.playerId,
        order.region,
        order.status,
        order.userId
      ].some(function (value) {
        return String(value || "").toLowerCase().includes(q);
      });
    });
  }

  res.json(orders);
});

app.get("/api/admin/stats", requireAdmin, function (req, res) {
  cleanOldOrders();

  const orders = readOrders();

  res.json({
    total: orders.length,
    pending: orders.filter(function (x) { return x.status === "PENDIENTE"; }).length,
    process: orders.filter(function (x) { return x.status === "EN PROCESO"; }).length,
    completed: orders.filter(function (x) { return x.status === "COMPLETADO"; }).length,
    cancelled: orders.filter(function (x) { return x.status === "CANCELADO"; }).length,
    sales: orders
      .filter(function (x) { return x.status !== "CANCELADO"; })
      .reduce(function (sum, x) { return sum + x.total; }, 0)
  });
});

app.patch("/api/admin/orders/:id", requireAdmin, function (req, res) {
  const allowed = ["PENDIENTE", "EN PROCESO", "COMPLETADO", "CANCELADO"];
  const status = String((req.body && req.body.status) || "");

  if (!allowed.includes(status)) {
    return res.status(400).json({ error: "Estado no permitido." });
  }

  const orders = readOrders();
  const index = orders.findIndex(function (order) {
    return order.id === req.params.id;
  });

  if (index < 0) {
    return res.status(404).json({ error: "Pedido no encontrado." });
  }

  orders[index].status = status;
  orders[index].updatedAt = new Date().toISOString();
  writeOrders(orders);

  res.json(orders[index]);
});

app.get("/health", function (req, res) {
  res.status(200).send("OK");
});

app.get("*", function (req, res) {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

cleanOldOrders();

app.listen(PORT, "0.0.0.0", function () {
  console.log("Julisita Vtas funcionando en puerto " + PORT);
});
