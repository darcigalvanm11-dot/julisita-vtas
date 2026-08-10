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

const THREE_MONTHS_MS = 90 * 24 * 60 * 60 * 1000;

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(DB)) {
  fs.writeFileSync(DB, "[]", "utf8");
}

if (!fs.existsSync(USERS_DB)) {
  fs.writeFileSync(USERS_DB, "[]", "utf8");
}

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));


/* =========================================================
   PRODUCTOS
========================================================= */

const PRODUCTS = [
  ["U110", "Única por ID", "110", 3800],
  ["U342", "Única por ID", "342", 10200],
  ["U572", "Única por ID", "572", 15400],
  ["U1166", "Única por ID", "1.166", 28000],
  ["U2398", "Única por ID", "2.398", 55600],
  ["U6160", "Única por ID", "6.160", 137500],

  ["I110", "Ilimitada", "110", 4000],
  ["I342", "Ilimitada", "342", 11000],
  ["I572", "Ilimitada", "572", 17000],
  ["I1166", "Ilimitada", "1.166", 32000],
  ["I2398", "Ilimitada", "2.398", 64000],
  ["I6160", "Ilimitada", "6.160", 158000]
].map(([id, type, diamonds, price]) => ({
  id,
  type,
  diamonds,
  price
}));


/* =========================================================
   ARCHIVOS JSON
========================================================= */

function readOrders() {
  try {
    const data = JSON.parse(fs.readFileSync(DB, "utf8"));
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function writeOrders(orders) {
  fs.writeFileSync(
    DB,
    JSON.stringify(orders, null, 2),
    "utf8"
  );
}

function readUsers() {
  try {
    const data = JSON.parse(fs.readFileSync(USERS_DB, "utf8"));
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(
    USERS_DB,
    JSON.stringify(users, null, 2),
    "utf8"
  );
}


/* =========================================================
   LIMPIEZA AUTOMÁTICA DE PEDIDOS DE MÁS DE 3 MESES
========================================================= */

function cleanOldOrders() {
  const orders = readOrders();
  const now = Date.now();

  const filtered = orders.filter(order => {
    const date = new Date(order.createdAt).getTime();

    if (!Number.isFinite(date)) {
      return true;
    }

    return now - date < THREE_MONTHS_MS;
  });

  if (filtered.length !== orders.length) {
    writeOrders(filtered);
    console.log(
      `Limpieza automática: ${orders.length - filtered.length} pedido(s) eliminado(s).`
    );
  }
}


/* =========================================================
   SEGURIDAD DE CONTRASEÑAS
========================================================= */

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto
    .pbkdf2Sync(
      password,
      salt,
      120000,
      64,
      "sha512"
    )
    .toString("hex");

  return {
    salt,
    hash
  };
}

function verifyPassword(password, user) {
  const hash = crypto
    .pbkdf2Sync(
      password,
      user.salt,
      120000,
      64,
      "sha512"
    )
    .toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(user.passwordHash, "hex")
  );
}


/* =========================================================
   TOKENS
========================================================= */

function adminToken(password) {
  return crypto
    .createHash("sha256")
    .update("julista-admin:" + password)
    .digest("hex");
}

function userToken(userId) {
  const secret = process.env.SESSION_SECRET || "JULISITA-SESSION-2026";

  return crypto
    .createHmac("sha256", secret)
    .update(String(userId))
    .digest("hex");
}


/* =========================================================
   AUTENTICACIÓN DE ADMINISTRADORA
========================================================= */

function requireAdmin(req, res, next) {
  const got = String(req.headers.authorization || "");

  if (got !== "Bearer " + adminToken(ADMIN_PASSWORD)) {
    return res.status(401).json({
      error: "Sesión de administradora no válida."
    });
  }

  next();
}


/* =========================================================
   AUTENTICACIÓN DE CLIENTES
========================================================= */

function getUserFromRequest(req) {
  const got = String(req.headers.authorization || "");

  if (!got.startsWith("Bearer ")) {
    return null;
  }

  const token = got.slice(7).trim();

  if (!token) {
    return null;
  }

  const users = readUsers();

  for (const user of users) {
    const expected = userToken(user.id);

    if (
      token.length === expected.length &&
      crypto.timingSafeEqual(
        Buffer.from(token),
        Buffer.from(expected)
      )
    ) {
      return user;
    }
  }

  return null;
}

function requireUser(req, res, next) {
  const user = getUserFromRequest(req);

  if (!user) {
    return res.status(401).json({
      error: "Debes iniciar sesión para continuar."
    });
  }

  req.user = user;
  next();
}


/* =========================================================
   PRODUCTOS
========================================================= */

app.get("/api/products", (req, res) => {
  res.json(PRODUCTS);
});


/* =========================================================
   CREAR CUENTA
========================================================= */

app.post("/api/auth/register", (req, res) => {
  const body = req.body || {};

  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!name || !email || !password) {
    return res.status(400).json({
      error: "Completa nombre, correo y contraseña."
    });
  }

  if (name.length < 2) {
    return res.status(400).json({
      error: "El nombre es demasiado corto."
    });
  }

  if (name.length > 100) {
    return res.status(400).json({
      error: "El nombre es demasiado largo."
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      error: "Introduce un correo válido."
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error: "La contraseña debe tener al menos 6 caracteres."
    });
  }

  if (password.length > 200) {
    return res.status(400).json({
      error: "La contraseña es demasiado larga."
    });
  }

  const users = readUsers();

  const exists = users.some(
    user => user.email.toLowerCase() === email
  );

  if (exists) {
    return res.status(409).json({
      error: "Ya existe una cuenta con ese correo."
    });
  }

  const id =
    "USR-" +
    crypto.randomBytes(6).toString("hex").toUpperCase();

  const secured = hashPassword(password);

  const now = new Date().toISOString();

  const user = {
    id,
    name: name.slice(0, 100),
    email: email.slice(0, 150),
    passwordHash: secured.hash,
    salt: secured.salt,
    createdAt: now
  };

  users.push(user);
  writeUsers(users);

  res.status(201).json({
    message: "Cuenta creada correctamente.",
    user: {
      id: user.id,
      name: user.name,
      email: user.email
    },
    token: userToken(user.id)
  });
});


/* =========================================================
   INICIAR SESIÓN
========================================================= */

app.post("/api/auth/login", (req, res) => {
  const body = req.body || {};

  const email = String(body.email || "")
    .trim()
    .toLowerCase();

  const password = String(body.password || "");

  if (!email || !password) {
    return res.status(400).json({
      error: "Introduce tu correo y contraseña."
    });
  }

  const users = readUsers();

  const user = users.find(
    x => x.email.toLowerCase() === email
  );

  if (!user) {
    return res.status(401).json({
      error: "Correo o contraseña incorrectos."
    });
  }

  let valid = false;

  try {
    valid = verifyPassword(password, user);
  } catch {
    valid = false;
  }

  if (!valid) {
    return res.status(401).json({
      error: "Correo o contraseña incorrectos."
    });
  }

  res.json({
    message: "Inicio de sesión correcto.",
    user: {
      id: user.id,
      name: user.name,
      email: user.email
    },
    token: userToken(user.id)
  });
});


/* =========================================================
   INFORMACIÓN DE LA CUENTA
========================================================= */

app.get("/api/auth/me", requireUser, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      createdAt: req.user.createdAt
    }
  });
});


/* =========================================================
   PEDIDOS DEL CLIENTE
========================================================= */

app.get("/api/my/orders", requireUser, (req, res) => {
  cleanOldOrders();

  const orders = readOrders()
    .filter(order => order.userId === req.user.id)
    .sort((a, b) =>
      String(b.createdAt).localeCompare(
        String(a.createdAt)
      )
    );

  res.json(
    orders.map(order => ({
      id: order.id,
      customer: order.customer,
      playerId: order.playerId,
      region: order.region,
      notes: order.notes,
      items: order.items,
      total: order.total,
      status: order.status,
      createdAt: order.createdAt,
      updatedAt: order.updatedAt
    }))
  );
});


/* =========================================================
   CREAR PEDIDO
========================================================= */

app.post("/api/orders", requireUser, (req, res) => {
  cleanOldOrders();

  const b = req.body || {};

  const customer = String(
    b.customer || req.user.name || ""
  ).trim();

  const playerId = String(
    b.playerId || ""
  ).trim();

  const region = String(
    b.region || ""
  ).trim();

  const itemsIn = Array.isArray(b.items)
    ? b.items
    : [];

  if (
    !customer ||
    !playerId ||
    !region ||
    !itemsIn.length
  ) {
    return res.status(400).json({
      error:
        "Completa nombre, ID, región y agrega productos."
    });
  }

  const items = [];

  for (const raw of itemsIn) {
    const p = PRODUCTS.find(
      x => x.id === raw.productId
    );

    const qty = Math.max(
      1,
      Math.min(
        99,
        parseInt(raw.qty, 10) || 1
      )
    );

    if (!p) {
      return res.status(400).json({
        error: "Uno de los productos no existe."
      });
    }

    items.push({
      ...p,
      qty
    });
  }

  const total = items.reduce(
    (sum, x) => sum + x.price * x.qty,
    0
  );

  const orders = readOrders();

  const now = new Date();

  const order = {
    id:
      "JV-" +
      now
        .getTime()
        .toString()
        .slice(-8),

    userId: req.user.id,

    customer: customer.slice(0, 100),

    playerId: playerId.slice(0, 80),

    region: region.slice(0, 40),

    notes: String(
      b.notes || ""
    )
      .trim()
      .slice(0, 500),

    items,

    total,

    status: "PENDIENTE",

    createdAt: now.toISOString(),

    updatedAt: now.toISOString()
  };

  orders.push(order);

  writeOrders(orders);

  res.status(201).json({
    id: order.id,
    total: order.total,
    status: order.status,
    createdAt: order.createdAt
  });
});


/* =========================================================
   CONSULTAR UN PEDIDO PROPIO
========================================================= */

app.get(
  "/api/my/orders/:id",
  requireUser,
  (req, res) => {
    cleanOldOrders();

    const id = String(
      req.params.id || ""
    )
      .trim()
      .toUpperCase();

    const order = readOrders().find(
      x =>
        String(x.id).toUpperCase() === id &&
        x.userId === req.user.id
    );

    if (!order) {
      return res.status(404).json({
        error:
          "No encontramos ese pedido en tu cuenta."
      });
    }

    res.json({
      id: order.id,
      status: order.status,
      customer: order.customer,
      playerId: order.playerId,
      region: order.region,
      notes: order.notes,
      items: order.items,
      total: order.total,
      createdAt: order.createdAt,
      updatedAt: order.updatedAt
    });
  }
);


/* =========================================================
   LOGIN ADMINISTRADORA
========================================================= */

app.post("/api/admin/login", (req, res) => {
  const password = String(
    req.body?.password || ""
  );

  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({
      error: "Contraseña incorrecta."
    });
  }

  res.json({
    token: adminToken(ADMIN_PASSWORD)
  });
});


/* =========================================================
   TODOS LOS PEDIDOS — SOLO ADMIN
========================================================= */

app.get(
  "/api/admin/orders",
  requireAdmin,
  (req, res) => {
    cleanOldOrders();

    const q = String(
      req.query.q || ""
    )
      .trim()
      .toLowerCase();

    let orders = readOrders().sort(
      (a, b) =>
        String(b.createdAt).localeCompare(
          String(a.createdAt)
        )
    );

    if (q) {
      orders = orders.filter(o =>
        [
          o.id,
          o.customer,
          o.playerId,
          o.region,
          o.status,
          o.userId
        ].some(v =>
          String(v || "")
            .toLowerCase()
            .includes(q)
        )
      );
    }

    res.json(orders);
  }
);


/* =========================================================
   ESTADÍSTICAS — SOLO ADMIN
========================================================= */

app.get(
  "/api/admin/stats",
  requireAdmin,
  (req, res) => {
    cleanOldOrders();

    const o = readOrders();

    res.json({
      total: o.length,

      pending: o.filter(
        x => x.status === "PENDIENTE"
      ).length,

      process: o.filter(
        x => x.status === "EN PROCESO"
      ).length,

      completed: o.filter(
        x => x.status === "COMPLETADO"
      ).length,

      cancelled: o.filter(
        x => x.status === "CANCELADO"
      ).length,

      sales: o
        .filter(
          x => x.status !== "CANCELADO"
        )
        .reduce(
          (s, x) => s + x.total,
          0
        )
    });
  }
);


/* =========================================================
   CAMBIAR ESTADO — SOLO ADMIN
========================================================= */

app.patch(
  "/api/admin/orders/:id",
  requireAdmin,
  (req, res) => {
    const allowed = [
      "PENDIENTE",
      "EN PROCESO",
      "COMPLETADO",
      "CANCELADO"
    ];

    const status = String(
      req.body?.status || ""
    );

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error: "Estado no permitido."
      });
    }

    const orders = readOrders();

    const i = orders.findIndex(
      x => x.id === req.params.id
    );

    if (i < 0) {
      return res.status(404).json({
        error: "Pedido no encontrado."
      });
    }

    orders[i].status = status;

    orders[i].updatedAt =
      new Date().toISOString();

    writeOrders(orders);

    res.json(orders[i]);
  }
);


/* =========================================================
   RUTA PRINCIPAL
========================================================= */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});


/* =========================================================
   INICIO
========================================================= */

cleanOldOrders();

app.listen(PORT, () => {
  console.log(
    `Julisita Vtas: http://localhost:${PORT}`
  );
});}
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
