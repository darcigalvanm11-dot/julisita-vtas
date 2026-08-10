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

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(DB)) {
  fs.writeFileSync(DB, "[]", "utf8");
}

if (!fs.existsSync(USERS_DB)) {
  fs.writeFileSync(USERS_DB, "[]", "utf8");
}


/* =========================
   PRODUCTOS
========================= */

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


/* =========================
   BASE DE DATOS
========================= */

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


/* =========================
   LIMPIAR PEDIDOS DE MÁS
   DE 3 MESES
========================= */

function cleanOldOrders() {
  const orders = readOrders();
  const now = Date.now();
  const THREE_MONTHS = 90 * 24 * 60 * 60 * 1000;

  const validOrders = orders.filter(order => {
    const created = new Date(order.createdAt).getTime();

    if (!Number.isFinite(created)) {
      return true;
    }

    return now - created < THREE_MONTHS;
  });

  if (validOrders.length !== orders.length) {
    writeOrders(validOrders);
    console.log(
      "Pedidos eliminados por antigüedad:",
      orders.length - validOrders.length
    );
  }
}


/* =========================
   CONTRASEÑAS
========================= */

function hashPassword(password, salt) {
  return crypto
    .pbkdf2Sync(
      password,
      salt,
      120000,
      64,
      "sha512"
    )
    .toString("hex");
}

function createPassword(password) {
  const salt = crypto
    .randomBytes(16)
    .toString("hex");

  const hash = hashPassword(password, salt);

  return {
    salt,
    hash
  };
}

function checkPassword(password, user) {
  const hash = hashPassword(
    password,
    user.salt
  );

  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(user.passwordHash, "hex")
  );
}


/* =========================
   TOKENS
========================= */

function adminToken() {
  return crypto
    .createHash("sha256")
    .update("julista-admin:" + ADMIN_PASSWORD)
    .digest("hex");
}

function userToken(userId) {
  const secret =
    process.env.SESSION_SECRET ||
    "JULISITA-SESSION-2026";

  return crypto
    .createHmac("sha256", secret)
    .update(String(userId))
    .digest("hex");
}


/* =========================
   AUTENTICACIÓN ADMIN
========================= */

function requireAdmin(req, res, next) {
  const authorization =
    String(req.headers.authorization || "");

  if (
    authorization !==
    "Bearer " + adminToken()
  ) {
    return res.status(401).json({
      error: "Sesión de administradora no válida."
    });
  }

  next();
}


/* =========================
   AUTENTICACIÓN CLIENTE
========================= */

function getUser(req) {
  const authorization =
    String(req.headers.authorization || "");

  if (!authorization.startsWith("Bearer ")) {
    return null;
  }

  const token = authorization
    .slice(7)
    .trim();

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
  const user = getUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Debes iniciar sesión."
    });
  }

  req.user = user;
  next();
}


/* =========================
   PRODUCTOS
========================= */

app.get("/api/products", (req, res) => {
  res.json(PRODUCTS);
});


/* =========================
   REGISTRO
========================= */

app.post("/api/auth/register", (req, res) => {
  const name = String(
    req.body?.name || ""
  ).trim();

  const email = String(
    req.body?.email || ""
  ).trim()
   .toLowerCase();

  const password = String(
    req.body?.password || ""
  );

  if (!name || !email || !password) {
    return res.status(400).json({
      error:
        "Completa nombre, correo y contraseña."
    });
  }

  if (name.length < 2) {
    return res.status(400).json({
      error: "El nombre es demasiado corto."
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      error: "Introduce un correo válido."
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error:
        "La contraseña debe tener al menos 6 caracteres."
    });
  }

  const users = readUsers();

  const exists = users.some(
    user => user.email === email
  );

  if (exists) {
    return res.status(409).json({
      error:
        "Ya existe una cuenta con ese correo."
    });
  }

  const secured =
    createPassword(password);

  const user = {
    id:
      "USR-" +
      crypto
        .randomBytes(6)
        .toString("hex")
        .toUpperCase(),

    name: name.slice(0, 100),

    email: email.slice(0, 150),

    passwordHash: secured.hash,

    salt: secured.salt,

    createdAt:
      new Date().toISOString()
  };

  users.push(user);
  writeUsers(users);

  res.status(201).json({
    message:
      "Cuenta creada correctamente.",

    user: {
      id: user.id,
      name: user.name,
      email: user.email
    },

    token: userToken(user.id)
  });
});


/* =========================
   LOGIN CLIENTE
========================= */

app.post("/api/auth/login", (req, res) => {
  const email = String(
    req.body?.email || ""
  ).trim()
   .toLowerCase();

  const password = String(
    req.body?.password || ""
  );

  const users = readUsers();

  const user = users.find(
    x => x.email === email
  );

  if (!user) {
    return res.status(401).json({
      error:
        "Correo o contraseña incorrectos."
    });
  }

  let valid = false;

  try {
    valid = checkPassword(
      password,
      user
    );
  } catch {
    valid = false;
  }

  if (!valid) {
    return res.status(401).json({
      error:
        "Correo o contraseña incorrectos."
    });
  }

  res.json({
    message:
      "Inicio de sesión correcto.",

    user: {
      id: user.id,
      name: user.name,
      email: user.email
    },

    token: userToken(user.id)
  });
});


/* =========================
   MI CUENTA
========================= */

app.get(
  "/api/auth/me",
  requireUser,
  (req, res) => {
    res.json({
      user: {
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
        createdAt: req.user.createdAt
      }
    });
  }
);


/* =========================
   MIS PEDIDOS
========================= */

app.get(
  "/api/my/orders",
  requireUser,
  (req, res) => {
    cleanOldOrders();

    const orders = readOrders()
      .filter(
        order =>
          order.userId === req.user.id
      )
      .sort(
        (a, b) =>
          new Date(b.createdAt) -
          new Date(a.createdAt)
      );

    res.json(orders);
  }
);


/* =========================
   CREAR PEDIDO
========================= */

app.post(
  "/api/orders",
  requireUser,
  (req, res) => {
    cleanOldOrders();

    const body = req.body || {};

    const customer = String(
      body.customer ||
      req.user.name ||
      ""
    ).trim();

    const playerId = String(
      body.playerId || ""
    ).trim();

    const region = String(
      body.region || ""
    ).trim();

    const itemsIn =
      Array.isArray(body.items)
        ? body.items
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
      const product =
        PRODUCTS.find(
          p => p.id === raw.productId
        );

      if (!product) {
        return res.status(400).json({
          error:
            "Uno de los productos no existe."
        });
      }

      const qty = Math.max(
        1,
        Math.min(
          99,
          parseInt(raw.qty, 10) || 1
        )
      );

      items.push({
        ...product,
        qty
      });
    }

    const total = items.reduce(
      (sum, item) =>
        sum +
        item.price *
        item.qty,
      0
    );

    const orders = readOrders();

    const now =
      new Date().toISOString();

    const order = {
      id:
        "JV-" +
        Date.now()
          .toString()
          .slice(-8),

      userId:
        req.user.id,

      customer:
        customer.slice(0, 100),

      playerId:
        playerId.slice(0, 80),

      region:
        region.slice(0, 40),

      notes:
        String(
          body.notes || ""
        )
        .trim()
        .slice(0, 500),

      items,

      total,

      status:
        "PENDIENTE",

      createdAt:
        now,

      updatedAt:
        now
    };

    orders.push(order);

    writeOrders(orders);

    res.status(201).json({
      id: order.id,
      total: order.total,
      status: order.status,
      createdAt:
        order.createdAt
    });
  }
);


/* =========================
   PEDIDO PROPIO
========================= */

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

    const order =
      readOrders().find(
        x =>
          String(x.id)
            .toUpperCase() === id &&
          x.userId === req.user.id
      );

    if (!order) {
      return res.status(404).json({
        error:
          "No encontramos ese pedido en tu cuenta."
      });
    }

    res.json(order);
  }
);


/* =========================
   LOGIN ADMIN
========================= */

app.post(
  "/api/admin/login",
  (req, res) => {
    const password = String(
      req.body?.password || ""
    );

    if (
      password !==
      ADMIN_PASSWORD
    ) {
      return res.status(401).json({
        error:
          "Contraseña incorrecta."
      });
    }

    res.json({
      token:
        adminToken()
    });
  }
);


/* =========================
   PEDIDOS ADMIN
========================= */

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

    let orders =
      readOrders().sort(
        (a, b) =>
          new Date(b.createdAt) -
          new Date(a.createdAt)
      );

    if (q) {
      orders =
        orders.filter(
          order =>
            [
              order.id,
              order.customer,
              order.playerId,
              order.region,
              order.status,
              order.userId
            ].some(
              value =>
                String(value || "")
                  .toLowerCase()
                  .includes(q)
            )
        );
    }

    res.json(orders);
  }
);


/* =========================
   ESTADÍSTICAS ADMIN
========================= */

app.get(
  "/api/admin/stats",
  requireAdmin,
  (req, res) => {
    cleanOldOrders();

    const orders =
      readOrders();

    res.json({
      total:
        orders.length,

      pending:
        orders.filter(
          x =>
            x.status ===
            "PENDIENTE"
        ).length,

      process:
        orders.filter(
          x =>
            x.status ===
            "EN PROCESO"
        ).length,

      completed:
        orders.filter(
          x =>
            x.status ===
            "COMPLETADO"
        ).length,

      cancelled:
        orders.filter(
          x =>
            x.status ===
            "CANCELADO"
        ).length,

      sales:
        orders
          .filter(
            x =>
              x.status !==
              "CANCELADO"
          )
          .reduce(
            (sum, x) =>
              sum + x.total,
            0
          )
    });
  }
);


/* =========================
   CAMBIAR ESTADO
========================= */

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

    const status =
      String(
        req.body?.status || ""
      );

    if (
      !allowed.includes(status)
    ) {
      return res.status(400).json({
        error:
          "Estado no permitido."
      });
    }

    const orders =
      readOrders();

    const index =
      orders.findIndex(
        order =>
          order.id ===
          req.params.id
      );

    if (index < 0) {
      return res.status(404).json({
        error:
          "Pedido no encontrado."
      });
    }

    orders[index].status =
      status;

    orders[index].updatedAt =
      new Date().toISOString();

    writeOrders(orders);

    res.json(
      orders[index]
    );
  }
);


/* =========================
   PÁGINA PRINCIPAL
========================= */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});


/* =========================
   INICIAR SERVIDOR
========================= */

cleanOldOrders();

app.listen(
  PORT,
  () => {
    console.log(
      `Julisita Vtas funcionando en el puerto ${PORT}`
    );
  }
);
