const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "JULISITA2026";

const DATA_DIR = path.join(__dirname, "data");
const DB = path.join(DATA_DIR, "orders.json");
const USERS_DB = path.join(DATA_DIR, "users.json");
const SESSIONS_DB = path.join(DATA_DIR, "sessions.json");

fs.mkdirSync(DATA_DIR, { recursive: true });
for (const file of [DB, USERS_DB, SESSIONS_DB]) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, "[]", "utf8");
}

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const PRODUCTS = [
  ["U110","Única por ID","110",3800],
  ["U342","Única por ID","342",10200],
  ["U572","Única por ID","572",15400],
  ["U1166","Única por ID","1.166",28000],
  ["U2398","Única por ID","2.398",55600],
  ["U6160","Única por ID","6.160",137500],
  ["I110","Ilimitada","110",4000],
  ["I342","Ilimitada","342",11000],
  ["I572","Ilimitada","572",17000],
  ["I1166","Ilimitada","1.166",32000],
  ["I2398","Ilimitada","2.398",64000],
  ["I6160","Ilimitada","6.160",158000]
].map(([id,type,diamonds,price]) => ({id,type,diamonds,price}));

function readJson(file) {
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

/*
  Los pedidos se conservan durante 3 meses desde createdAt.
  La limpieza se hace automáticamente cada vez que se leen los pedidos.
*/
function threeMonthsAgo() {
  const d = new Date();
  d.setMonth(d.getMonth() - 3);
  return d;
}

function readOrders() {
  const orders = readJson(DB);
  const cutoff = threeMonthsAgo();

  const kept = orders.filter(order => {
    const created = new Date(order.createdAt);
    return Number.isNaN(created.getTime()) || created >= cutoff;
  });

  if (kept.length !== orders.length) writeJson(DB, kept);
  return kept;
}

function readUsers() {
  return readJson(USERS_DB);
}

function writeUsers(users) {
  writeJson(USERS_DB, users);
}

function readSessions() {
  return readJson(SESSIONS_DB);
}

function writeSessions(sessions) {
  writeJson(SESSIONS_DB, sessions);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  try {
    const actual = crypto.scryptSync(password, salt, 64).toString("hex");
    return crypto.timingSafeEqual(
      Buffer.from(actual, "hex"),
      Buffer.from(expectedHash, "hex")
    );
  } catch {
    return false;
  }
}

function createSession(userId) {
  const sessions = readSessions();
  const token = crypto.randomBytes(32).toString("hex");
  const now = new Date();
  const expiresAt = new Date(now);
  expiresAt.setDate(expiresAt.getDate() + 30);

  sessions.push({
    token,
    userId,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString()
  });

  writeSessions(sessions);
  return token;
}

function getUserFromSession(req) {
  const header = String(req.headers.authorization || "");
  if (!header.startsWith("Bearer ")) return null;

  const token = header.slice(7).trim();
  if (!token) return null;

  const sessions = readSessions();
  const now = Date.now();

  const valid = sessions.filter(s => new Date(s.expiresAt).getTime() > now);
  if (valid.length !== sessions.length) writeSessions(valid);

  const session = valid.find(s => s.token === token);
  if (!session) return null;

  return readUsers().find(u => u.id === session.userId) || null;
}

function requireUser(req, res, next) {
  const user = getUserFromSession(req);
  if (!user) {
    return res.status(401).json({ error: "Inicia sesión para continuar." });
  }
  req.user = user;
  next();
}

function authToken(password) {
  return crypto.createHash("sha256")
    .update("julista-admin:" + password)
    .digest("hex");
}

function requireAdmin(req, res, next) {
  const got = String(req.headers.authorization || "");
  if (got !== "Bearer " + authToken(ADMIN_PASSWORD)) {
    return res.status(401).json({ error: "Sesión de administradora no válida." });
  }
  next();
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt
  };
}

/* =========================
   PRODUCTOS
========================= */

app.get("/api/products", (req, res) => res.json(PRODUCTS));

/* =========================
   CUENTAS DE CLIENTES
========================= */

app.post("/api/auth/register", (req, res) => {
  const name = String(req.body?.name || "").trim();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (name.length < 2) {
    return res.status(400).json({ error: "Escribe tu nombre." });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Escribe un correo válido." });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "La contraseña debe tener mínimo 6 caracteres." });
  }

  const users = readUsers();

  if (users.some(u => u.email === email)) {
    return res.status(409).json({ error: "Ya existe una cuenta con ese correo." });
  }

  const { salt, hash } = hashPassword(password);
  const now = new Date();

  const user = {
    id: "USR-" + crypto.randomBytes(5).toString("hex").toUpperCase(),
    name: name.slice(0, 100),
    email,
    passwordSalt: salt,
    passwordHash: hash,
    createdAt: now.toISOString()
  };

  users.push(user);
  writeUsers(users);

  const token = createSession(user.id);

  res.status(201).json({
    user: publicUser(user),
    token
  });
});

app.post("/api/auth/login", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  const user = readUsers().find(u => u.email === email);

  if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    return res.status(401).json({ error: "Correo o contraseña incorrectos." });
  }

  const token = createSession(user.id);

  res.json({
    user: publicUser(user),
    token
  });
});

app.get("/api/auth/me", requireUser, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post("/api/auth/logout", (req, res) => {
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

  if (token) {
    writeSessions(readSessions().filter(s => s.token !== token));
  }

  res.json({ ok: true });
});

/* =========================
   PEDIDOS DEL CLIENTE
========================= */

app.get("/api/my/orders", requireUser, (req, res) => {
  const orders = readOrders()
    .filter(order => order.userId === req.user.id)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

  res.json(orders);
});

app.post("/api/orders", requireUser, (req, res) => {
  const b = req.body || {};
  const customer = String(b.customer || req.user.name || "").trim();
  const playerId = String(b.playerId || "").trim();
  const region = String(b.region || "").trim();
  const itemsIn = Array.isArray(b.items) ? b.items : [];

  if (!customer || !playerId || !region || !itemsIn.length) {
    return res.status(400).json({
      error: "Completa nombre, ID, región y agrega productos."
    });
  }

  const items = [];

  for (const raw of itemsIn) {
    const p = PRODUCTS.find(x => x.id === raw.productId);
    const qty = Math.max(1, Math.min(99, parseInt(raw.qty, 10) || 1));

    if (!p) {
      return res.status(400).json({
        error: "Uno de los productos no existe."
      });
    }

    items.push({ ...p, qty });
  }

  const total = items.reduce((sum, x) => sum + x.price * x.qty, 0);
  const orders = readOrders();
  const now = new Date();

  const order = {
    id: "JV-" + now.getTime().toString().slice(-8),
    userId: req.user.id,
    customer: customer.slice(0, 100),
    playerId: playerId.slice(0, 80),
    region: region.slice(0, 40),
    notes: String(b.notes || "").trim().slice(0, 500),
    items,
    total,
    status: "PENDIENTE",
    createdAt: now.toISOString(),
    updatedAt: now.toISOString()
  };

  orders.push(order);
  writeJson(DB, orders);

  res.status(201).json({
    id: order.id,
    total: order.total,
    status: order.status,
    createdAt: order.createdAt
  });
});

/*
  La consulta pública por número de pedido se elimina.
  Así un cliente no puede introducir el ID de otra persona
  para ver sus datos. El historial se consulta desde /api/my/orders.
*/

/* =========================
   ADMINISTRADORA
========================= */

app.post("/api/admin/login", (req, res) => {
  const password = String(req.body?.password || "");

  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Contraseña incorrecta." });
  }

  res.json({ token: authToken(ADMIN_PASSWORD) });
});

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();

  let orders = readOrders()
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

  if (q) {
    orders = orders.filter(o =>
      [o.id, o.customer, o.playerId, o.region, o.status]
        .some(v => String(v).toLowerCase().includes(q))
    );
  }

  res.json(orders);
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const o = readOrders();

  res.json({
    total: o.length,
    pending: o.filter(x => x.status === "PENDIENTE").length,
    process: o.filter(x => x.status === "EN PROCESO").length,
    completed: o.filter(x => x.status === "COMPLETADO").length,
    cancelled: o.filter(x => x.status === "CANCELADO").length,
    sales: o
      .filter(x => x.status !== "CANCELADO")
      .reduce((s, x) => s + x.total, 0)
  });
});

app.patch("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const allowed = ["PENDIENTE", "EN PROCESO", "COMPLETADO", "CANCELADO"];
  const status = String(req.body?.status || "");

  if (!allowed.includes(status)) {
    return res.status(400).json({ error: "Estado no permitido." });
  }

  const orders = readOrders();
  const i = orders.findIndex(x => x.id === req.params.id);

  if (i < 0) {
    return res.status(404).json({ error: "Pedido no encontrado." });
  }

  orders[i].status = status;
  orders[i].updatedAt = new Date().toISOString();
  writeJson(DB, orders);

  res.json(orders[i]);
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Julisita Vtas: http://localhost:${PORT}`);
});
