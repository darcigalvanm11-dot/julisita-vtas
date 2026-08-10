
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "JULISITA2026";
const DB = path.join(__dirname, "data", "orders.json");

app.use(express.json({limit:"1mb"}));
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

function readOrders() {
  try { return JSON.parse(fs.readFileSync(DB,"utf8")); }
  catch { return []; }
}
function writeOrders(orders) {
  fs.writeFileSync(DB, JSON.stringify(orders,null,2), "utf8");
}
function authToken(password) {
  return crypto.createHash("sha256").update("julista-admin:"+password).digest("hex");
}
function requireAdmin(req,res,next) {
  const got = String(req.headers.authorization || "");
  if (got !== "Bearer "+authToken(ADMIN_PASSWORD)) {
    return res.status(401).json({error:"Sesión de administradora no válida."});
  }
  next();
}

app.get("/api/products", (req,res) => res.json(PRODUCTS));

app.post("/api/orders", (req,res) => {
  const b = req.body || {};
  const customer = String(b.customer || "").trim();
  const playerId = String(b.playerId || "").trim();
  const region = String(b.region || "").trim();
  const itemsIn = Array.isArray(b.items) ? b.items : [];

  if (!customer || !playerId || !region || !itemsIn.length)
    return res.status(400).json({error:"Completa nombre, ID, región y agrega productos."});

  const items = [];
  for (const raw of itemsIn) {
    const p = PRODUCTS.find(x => x.id === raw.productId);
    const qty = Math.max(1, Math.min(99, parseInt(raw.qty,10) || 1));
    if (!p) return res.status(400).json({error:"Uno de los productos no existe."});
    items.push({...p, qty});
  }

  const total = items.reduce((sum,x) => sum + x.price*x.qty, 0);
  const orders = readOrders();
  const now = new Date();
  const order = {
    id: "JV-" + now.getTime().toString().slice(-8),
    customer: customer.slice(0,100),
    playerId: playerId.slice(0,80),
    region: region.slice(0,40),
    notes: String(b.notes || "").trim().slice(0,500),
    items,
    total,
    status:"PENDIENTE",
    createdAt:now.toISOString(),
    updatedAt:now.toISOString()
  };
  orders.push(order);
  writeOrders(orders);
  res.status(201).json({
    id:order.id,
    total:order.total,
    status:order.status,
    createdAt:order.createdAt
  });
});

app.get("/api/orders/:id", (req,res) => {
  const id = String(req.params.id).trim().toUpperCase();
  const order = readOrders().find(x => x.id.toUpperCase() === id);
  if (!order) return res.status(404).json({error:"No encontramos ese pedido."});
  res.json({
    id:order.id, status:order.status, customer:order.customer,
    items:order.items, total:order.total, createdAt:order.createdAt,
    updatedAt:order.updatedAt
  });
});

app.post("/api/admin/login", (req,res) => {
  const password = String(req.body?.password || "");
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({error:"Contraseña incorrecta."});
  res.json({token:authToken(ADMIN_PASSWORD)});
});

app.get("/api/admin/orders", requireAdmin, (req,res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  let orders = readOrders().sort((a,b)=>b.createdAt.localeCompare(a.createdAt));
  if (q) {
    orders = orders.filter(o =>
      [o.id,o.customer,o.playerId,o.region,o.status]
      .some(v => String(v).toLowerCase().includes(q))
    );
  }
  res.json(orders);
});

app.get("/api/admin/stats", requireAdmin, (req,res) => {
  const o = readOrders();
  res.json({
    total:o.length,
    pending:o.filter(x=>x.status==="PENDIENTE").length,
    process:o.filter(x=>x.status==="EN PROCESO").length,
    completed:o.filter(x=>x.status==="COMPLETADO").length,
    cancelled:o.filter(x=>x.status==="CANCELADO").length,
    sales:o.filter(x=>x.status!=="CANCELADO").reduce((s,x)=>s+x.total,0)
  });
});

app.patch("/api/admin/orders/:id", requireAdmin, (req,res) => {
  const allowed = ["PENDIENTE","EN PROCESO","COMPLETADO","CANCELADO"];
  const status = String(req.body?.status || "");
  if (!allowed.includes(status))
    return res.status(400).json({error:"Estado no permitido."});
  const orders = readOrders();
  const i = orders.findIndex(x=>x.id===req.params.id);
  if (i<0) return res.status(404).json({error:"Pedido no encontrado."});
  orders[i].status = status;
  orders[i].updatedAt = new Date().toISOString();
  writeOrders(orders);
  res.json(orders[i]);
});

app.get("*", (req,res) =>
  res.sendFile(path.join(__dirname,"public","index.html"))
);

app.listen(PORT, () => console.log(`Julisita Vtas: http://localhost:${PORT}`));
