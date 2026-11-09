"use strict";
/* StreamAnime — logika bersama untuk Vercel Serverless Functions (api/).
   Refactor dari server.js: TANPA penyajian file statis dan TANPA listen().
   Dipakai oleh api/health.js, api/catalog.js, api/login.js, api/logout.js,
   dan api/admin/catalog.js. Tanpa dependensi (hanya modul bawaan Node). */
const crypto = require("crypto");
const seedData = require("./_seed");

const COOKIE_NAME = "sa_admin";
const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 hari
const BODY_LIMIT = 8 * 1024 * 1024; // 8 MB

/* ---------------- konfigurasi lingkungan ---------------- */
function adminPassword() { return process.env.ADMIN_PASSWORD || ""; }
function sessionSecret() { return process.env.SESSION_SECRET || adminPassword(); }
function firebaseBase() {
  const u = (process.env.FIREBASE_DB_URL || "").trim();
  return u ? u.replace(/\/+$/, "") : "";
}
function firebasePath() {
  return (process.env.FIREBASE_PATH || "streamanime/catalog").replace(/^\/+|\/+$/g, "");
}
function firebaseUrl() {
  if (!firebaseBase()) return null;
  let url = firebaseBase() + "/" + firebasePath() + ".json";
  if (process.env.FIREBASE_SECRET) url += "?auth=" + encodeURIComponent(process.env.FIREBASE_SECRET);
  return url;
}
function firebaseConfigured() { return !!firebaseUrl(); }

/* ---------------- util ---------------- */
function sendJson(res, status, obj, extraHeaders) {
  if (res.writableEnded) return;
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  }, extraHeaders || {}));
  res.end(body);
}
function methodNotAllowed(req, res, allowed) {
  sendJson(res, 405, { error: "Metode " + (req.method || "?") + " tidak diizinkan untuk endpoint ini." },
    { Allow: allowed.join(", ") });
}
function wrap(fn) {
  return async function (req, res) {
    try { await fn(req, res); }
    catch (err) {
      const status = err && err.status ? err.status : 500;
      try { sendJson(res, status, { error: err && err.message ? err.message : "Kesalahan server" }); }
      catch (e) { /* respons sudah terkirim */ }
    }
  };
}
function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (ba.length !== bb.length) {
    // tetap bandingkan dummy supaya waktu respons tidak membocorkan panjang
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    if (!req || typeof req.on !== "function") { resolve(""); return; }
    const chunks = [];
    let size = 0;
    let settled = false;
    req.on("data", (c) => {
      if (settled) return;
      size += c.length;
      if (size > BODY_LIMIT) {
        settled = true;
        reject(Object.assign(new Error("Body terlalu besar (maks 8 MB)"), { status: 413 }));
        if (typeof req.destroy === "function") req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => { if (!settled) { settled = true; resolve(Buffer.concat(chunks).toString("utf8")); } });
    req.on("error", (e) => { if (!settled) { settled = true; reject(e); } });
  });
}
/* Baca body JSON: tangani DUA kemungkinan —
   (a) req.body sudah diparse platform (objek / string / Buffer), atau
   (b) body masih berupa stream mentah yang harus dibaca dari req. */
async function readJsonBody(req) {
  if (req && req.body != null) {
    const b = req.body;
    if (typeof b === "object" && !Buffer.isBuffer(b)) return b;
    const raw = Buffer.isBuffer(b) ? b.toString("utf8") : String(b);
    if (!raw.trim()) return {};
    try { return JSON.parse(raw); }
    catch (e) { throw Object.assign(new Error("Body bukan JSON yang valid"), { status: 400 }); }
  }
  const raw = await readBody(req);
  if (!raw) return {};
  try { return JSON.parse(raw); }
  catch (e) { throw Object.assign(new Error("Body bukan JSON yang valid"), { status: 400 }); }
}
function parseCookies(req) {
  const out = {};
  const h = (req.headers && req.headers.cookie) || "";
  h.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i > 0) {
      try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); }
      catch (e) { out[part.slice(0, i).trim()] = part.slice(i + 1).trim(); }
    }
  });
  return out;
}
function isHttps(req) {
  const proto = ((req.headers && req.headers["x-forwarded-proto"]) || "").split(",")[0].trim();
  if (proto) return proto === "https";
  return !!(req.socket && req.socket.encrypted);
}
function clientIp(req) {
  const fwd = req.headers && req.headers["x-forwarded-for"];
  if (fwd) return String(fwd).split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

/* ---------------- token sesi (HMAC, stateless) ---------------- */
function signToken(exp) {
  const payload = String(exp);
  const sig = crypto.createHmac("sha256", sessionSecret()).update(payload).digest("base64url");
  return payload + "." + sig;
}
function verifyToken(token) {
  if (!token || !sessionSecret()) return false;
  const parts = String(token).split(".");
  if (parts.length !== 2) return false;
  const exp = Number(parts[0]);
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  const expected = crypto.createHmac("sha256", sessionSecret()).update(parts[0]).digest("base64url");
  return timingSafeEqualStr(parts[1], expected);
}
function isAuthed(req) {
  const cookies = parseCookies(req);
  return verifyToken(cookies[COOKIE_NAME] || "");
}

/* ---------------- rate limit login (best-effort per instance) ---------------- */
const loginFails = new Map(); // ip -> [timestamp,...]
function loginRateLimited(ip) {
  const now = Date.now();
  const arr = (loginFails.get(ip) || []).filter((t) => now - t < 5 * 60 * 1000);
  loginFails.set(ip, arr);
  return arr.length >= 5;
}
function recordLoginFail(ip) {
  const arr = loginFails.get(ip) || [];
  arr.push(Date.now());
  loginFails.set(ip, arr);
}

/* ---------------- Firebase REST ---------------- */
async function firebaseGet() {
  const url = firebaseUrl();
  if (!url) return null;
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error("Firebase GET gagal: HTTP " + r.status);
  return r.json(); // bisa null bila belum ada data
}
async function firebasePut(data) {
  const url = firebaseUrl();
  if (!url) throw new Error("Firebase belum dikonfigurasi");
  const r = await fetch(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!r.ok) throw new Error("Firebase PUT gagal: HTTP " + r.status);
  return r.json().catch(() => null);
}
function loadSeed() {
  if (seedData && Array.isArray(seedData.catalog)) return seedData.catalog;
  if (Array.isArray(seedData)) return seedData;
  return null;
}
/* Ambil katalog efektif: dari Firebase; bila Firebase kosong -> seed otomatis. */
/* Firebase RTDB tidak menyimpan array kosong: judul tanpa episode
   kembali dari GET tanpa kunci "episodes" sama sekali. Normalisasi
   bentuk judul di sini agar setiap konsumen API menerima bentuk utuh. */
function fixTitleShape(a) {
  if (!a || typeof a !== "object") a = {};
  if (!Array.isArray(a.episodes)) a.episodes = [];
  if (!Array.isArray(a.genre)) a.genre = a.genre ? [a.genre] : [];
  if (typeof a.rating !== "number") a.rating = 0;
  return a;
}
function fixCatalogShape(list) {
  return Array.isArray(list) ? list.map(fixTitleShape) : list;
}
async function getCatalogData() {
  if (!firebaseConfigured()) return { catalog: null, updatedAt: null, source: "unconfigured" };
  const data = await firebaseGet();
  if (data && Array.isArray(data.catalog) && data.catalog.length) {
    return { catalog: fixCatalogShape(data.catalog), updatedAt: data.updatedAt || null, source: "firebase" };
  }
  // Firebase belum punya data -> seed dari api/_seed.js
  const seed = loadSeed();
  if (seed && seed.length) {
    const payload = { catalog: seed, updatedAt: new Date().toISOString() };
    await firebasePut(payload);
    return { catalog: seed, updatedAt: payload.updatedAt, source: "seed" };
  }
  return { catalog: null, updatedAt: null, source: "empty" };
}

/* ---------------- validasi / sanitasi katalog ---------------- */
function slugify(s) {
  return String(s || "")
    .toLowerCase()
    .normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}
function isDateStr(s) { return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s); }
function todayStr() { return new Date().toISOString().slice(0, 10); }
function str(v, max) {
  if (v == null) return "";
  return String(v).slice(0, max || 10000);
}
function validateCatalog(input) {
  if (!Array.isArray(input)) return { error: "Katalog harus berupa array." };
  if (input.length > 500) return { error: "Katalog melebihi batas 500 judul." };
  const seenSlug = new Set();
  const out = [];
  for (let i = 0; i < input.length; i++) {
    const a = input[i] || {};
    const label = "Judul ke-" + (i + 1);
    const slug = slugify(a.slug || a.title || "");
    if (!slug) return { error: label + ": slug wajib diisi." };
    if (seenSlug.has(slug)) return { error: "Slug duplikat: \"" + slug + "\". Setiap anime harus punya slug unik." };
    seenSlug.add(slug);
    const title = str(a.title, 300).trim();
    if (!title) return { error: label + " (" + slug + "): judul wajib diisi." };
    let genre = [];
    if (a.genre != null) {
      if (!Array.isArray(a.genre)) return { error: title + ": genre harus berupa array." };
      genre = a.genre.slice(0, 12).map((g) => str(g, 60).trim()).filter(Boolean);
    }
    let year = parseInt(a.year, 10);
    if (!Number.isFinite(year)) year = new Date().getFullYear();
    if (year < 1900 || year > 2100) return { error: title + ": tahun harus antara 1900–2100." };
    let rating = Number(a.rating);
    if (!Number.isFinite(rating)) rating = 0;
    if (rating < 0 || rating > 10) return { error: title + ": rating harus antara 0–10." };
    const status = a.status === "Completed" ? "Completed" : a.status === "Ongoing" ? "Ongoing" : null;
    if (!status) return { error: title + ": status harus \"Ongoing\" atau \"Completed\"." };
    let updated = str(a.updated, 10).trim();
    if (!updated) updated = todayStr();
    if (!isDateStr(updated)) return { error: title + ": tanggal update harus format YYYY-MM-DD." };
    const poster = str(a.poster, 900000);
    if (poster.length > 900000) return { error: title + ": poster terlalu besar." };
    let episodesIn = [];
    if (a.episodes != null) {
      if (!Array.isArray(a.episodes)) return { error: title + ": episodes harus berupa array." };
      if (a.episodes.length > 2000) return { error: title + ": episode melebihi batas 2000." };
      episodesIn = a.episodes;
    }
    const seenN = new Set();
    const episodes = [];
    for (const epRaw of episodesIn) {
      const ep = epRaw || {};
      const n = parseInt(ep.n, 10);
      if (!Number.isFinite(n) || n <= 0) return { error: title + ": nomor episode harus bilangan bulat positif." };
      if (seenN.has(n)) return { error: title + ": nomor episode duplikat: " + n + "." };
      seenN.add(n);
      const epDate = str(ep.date, 10).trim();
      if (epDate && !isDateStr(epDate)) return { error: title + " episode " + n + ": tanggal harus format YYYY-MM-DD atau kosong." };
      episodes.push({
        n,
        title: str(ep.title, 500),
        date: epDate,
        src: str(ep.src, 5000).trim(),
        srcDrive: str(ep.srcDrive, 5000).trim(),
        srcMega: str(ep.srcMega, 5000).trim(),
      });
    }
    episodes.sort((x, y) => x.n - y.n);
    out.push({
      slug,
      title,
      alt: str(a.alt, 500),
      genre,
      year,
      rating,
      status,
      studio: str(a.studio, 300),
      updated,
      poster,
      synopsis: str(a.synopsis, 5000),
      episodes,
    });
  }
  return { catalog: out };
}

/* ---------------- handler per endpoint ---------------- */
const handleHealth = wrap(async (req, res) => {
  if (req.method !== "GET") { methodNotAllowed(req, res, ["GET"]); return; }
  let count = null;
  if (firebaseConfigured()) {
    try {
      const data = await firebaseGet();
      if (data && Array.isArray(data.catalog)) count = data.catalog.length;
    } catch (e) { count = null; }
  }
  sendJson(res, 200, {
    ok: true,
    storage: firebaseConfigured() ? "firebase" : "unconfigured",
    runtime: process.env.VERCEL ? "vercel" : "node",
    catalog: count,
  });
});

const handlePublicCatalog = wrap(async (req, res) => {
  if (req.method !== "GET") { methodNotAllowed(req, res, ["GET"]); return; }
  if (!firebaseConfigured()) { sendJson(res, 200, { catalog: null }); return; }
  const data = await getCatalogData();
  if (!data.catalog) { sendJson(res, 200, { catalog: null }); return; }
  sendJson(res, 200, { catalog: data.catalog, updatedAt: data.updatedAt });
});

const handleLogin = wrap(async (req, res) => {
  if (req.method !== "POST") { methodNotAllowed(req, res, ["POST"]); return; }
  if (!adminPassword()) {
    sendJson(res, 503, { error: "ADMIN_PASSWORD belum diatur di Environment Variables server." });
    return;
  }
  const ip = clientIp(req);
  if (loginRateLimited(ip)) {
    sendJson(res, 429, { error: "Terlalu banyak percobaan login gagal. Coba lagi dalam beberapa menit." });
    return;
  }
  const body = await readJsonBody(req);
  const given = body && body.password != null ? String(body.password) : "";
  if (!timingSafeEqualStr(given, adminPassword())) {
    recordLoginFail(ip);
    sendJson(res, 401, { error: "Password salah." });
    return;
  }
  loginFails.delete(ip);
  const exp = Date.now() + TOKEN_TTL_MS;
  const cookie = COOKIE_NAME + "=" + encodeURIComponent(signToken(exp)) +
    "; HttpOnly; SameSite=Lax; Path=/; Max-Age=" + Math.floor(TOKEN_TTL_MS / 1000) +
    (isHttps(req) ? "; Secure" : "");
  sendJson(res, 200, { ok: true }, { "Set-Cookie": cookie });
});

const handleLogout = wrap(async (req, res) => {
  if (req.method !== "POST") { methodNotAllowed(req, res, ["POST"]); return; }
  const cookie = COOKIE_NAME + "=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" + (isHttps(req) ? "; Secure" : "");
  sendJson(res, 200, { ok: true }, { "Set-Cookie": cookie });
});

const handleAdminCatalog = wrap(async (req, res) => {
  if (req.method === "GET") {
    if (!isAuthed(req)) { sendJson(res, 401, { error: "Belum login." }); return; }
    if (!firebaseConfigured()) {
      sendJson(res, 200, { catalog: null, source: "unconfigured", updatedAt: null });
      return;
    }
    const data = await getCatalogData();
    sendJson(res, 200, { catalog: data.catalog, source: data.source, updatedAt: data.updatedAt });
    return;
  }
  if (req.method === "PUT") {
    if (!isAuthed(req)) { sendJson(res, 401, { error: "Belum login." }); return; }
    if (!firebaseConfigured()) {
      sendJson(res, 503, { error: "Firebase belum dikonfigurasi (FIREBASE_DB_URL belum diatur), katalog tidak bisa disimpan." });
      return;
    }
    const body = await readJsonBody(req);
    const result = validateCatalog(body && body.catalog);
    if (result.error) { sendJson(res, 400, { error: result.error }); return; }
    const payload = { catalog: result.catalog, updatedAt: new Date().toISOString() };
    await firebasePut(payload);
    const episodes = result.catalog.reduce((s, a) => s + a.episodes.length, 0);
    sendJson(res, 200, { ok: true, count: result.catalog.length, episodes });
    return;
  }
  methodNotAllowed(req, res, ["GET", "PUT"]);
});

module.exports = {
  handleHealth,
  handlePublicCatalog,
  handleLogin,
  handleLogout,
  handleAdminCatalog,
  // diekspor juga untuk test / pemakaian ulang
  validateCatalog,
  slugify,
  fixTitleShape,
  fixCatalogShape,
  getCatalogData,
  firebaseConfigured,
  _internals: { signToken, verifyToken, isAuthed, readJsonBody, loadSeed },
};
