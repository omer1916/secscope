// Secure counterpart of vuln-express: used to measure false positives.
"use strict";

const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);
const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString("hex");

app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
      "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  next();
});

app.use(express.static(path.join(__dirname, "public"), { index: "index.html", dotfiles: "deny" }));

const users = new Map([["alice", { id: 1, role: "user" }]]);

// Simple fixed-window rate limiter for the login endpoint.
const attempts = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const entry = attempts.get(ip) || { start: now, count: 0 };
  if (now - entry.start > 60_000) {
    entry.start = now;
    entry.count = 0;
  }
  entry.count += 1;
  attempts.set(ip, entry);
  return entry.count > 5;
}

app.post("/api/login", (req, res) => {
  if (rateLimited(req.ip)) return res.status(429).json({ error: "too many attempts" });
  const user = typeof req.body.user === "string" ? users.get(req.body.user) : undefined;
  if (!user || typeof req.body.pass !== "string") {
    return res.status(401).json({ error: "invalid credentials" });
  }
  const sid = crypto.randomBytes(32).toString("hex");
  res.cookie("__Host-sid", sid, { httpOnly: true, secure: true, sameSite: "strict", path: "/" });
  res.json({ ok: true });
});

app.get("/api/greet", (req, res) => {
  const name = String(req.query.name || "world").slice(0, 50);
  res.json({ greeting: "Hello " + name });
});

app.use((req, res) => res.status(404).json({ error: "not found" }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => res.status(500).json({ error: "internal error" }));

app.listen(PORT, HOST, () => console.log(`clean-express on http://${HOST}:${PORT}`));
