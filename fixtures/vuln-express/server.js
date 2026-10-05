// Deliberately vulnerable Express app for SecScope tests. Loopback only. DO NOT DEPLOY.
"use strict";

const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const path = require("path");
const _ = require("lodash");

const app = express();
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = "changeme"; // hardcoded secret

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS: reflects any Origin and allows credentials.
app.use((req, res, next) => {
  if (req.headers.origin) {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});

// Serves public/ including app.js.map (source map exposed in production).
app.use(express.static(path.join(__dirname, "public")));

// --- tiny in-memory "MongoDB" with operator support, to model NoSQL injection ---
const users = [
  { id: 1, user: "alice", pass: "alice-pass", role: "user" },
  { id: 2, user: "admin", pass: "S3cure-admin!", role: "admin" },
];
function matches(doc, query) {
  return Object.entries(query).every(([key, cond]) => {
    if (cond && typeof cond === "object") {
      if ("$ne" in cond) return doc[key] !== cond.$ne;
      if ("$gt" in cond) return doc[key] > cond.$gt;
      if ("$regex" in cond) return new RegExp(cond.$regex).test(doc[key]);
      return false;
    }
    return doc[key] === cond;
  });
}
const findOne = (query) => users.find((u) => matches(u, query)) || null;

app.post("/api/login", (req, res) => {
  // NoSQL injection: {"user":"admin","pass":{"$ne":null}} logs in as admin.
  const found = findOne({ user: req.body.user, pass: req.body.pass });
  if (!found) return res.status(401).json({ error: "invalid credentials" });
  res.json({ token: signNone({ sub: found.id, role: found.role }) });
});

// Command injection
app.get("/api/ping", (req, res) => {
  exec("echo pinging " + req.query.host, (err, stdout) => {
    res.type("text/plain").send(err ? String(err) : stdout);
  });
});

// eval of user input
app.get("/api/calc", (req, res) => {
  try {
    res.json({ result: eval(req.query.expr) });
  } catch (e) {
    res.status(500).send(e.stack); // stack trace leak
  }
});

// Prototype pollution sink via vulnerable lodash.merge (old lodash version).
app.post("/api/settings", (req, res) => {
  const settings = _.merge({}, req.body);
  res.json(settings);
});

// JWT verification that accepts alg "none".
function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}
function signNone(payload) {
  const header = b64url({ alg: "HS256", typ: "JWT" });
  const body = b64url(payload);
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(header + "." + body).digest("base64url");
  return header + "." + body + "." + sig;
}
function verify(token) {
  const [h, b, s] = String(token || "").split(".");
  if (!h || !b) return null;
  const header = JSON.parse(Buffer.from(h, "base64url").toString());
  if (header.alg === "none") return JSON.parse(Buffer.from(b, "base64url").toString());
  const expected = crypto.createHmac("sha256", JWT_SECRET).update(h + "." + b).digest("base64url");
  return s === expected ? JSON.parse(Buffer.from(b, "base64url").toString()) : null;
}

app.get("/api/admin", (req, res) => {
  const claims = verify((req.headers.authorization || "").replace(/^Bearer /, ""));
  if (!claims || claims.role !== "admin") return res.status(403).json({ error: "forbidden" });
  res.json({ secret: "admin area", users });
});

app.listen(PORT, HOST, () => console.log(`vuln-express on http://${HOST}:${PORT}`));
