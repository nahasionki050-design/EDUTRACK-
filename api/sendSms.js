/**
 * EduTrack CBC â€” SMS backend for Vercel (hardened for production).
 *
 * Request shapes (JSON POST):
 *   School send      { schoolCode, recipients:[{phone,message}] }
 *   Password-reset   { purpose:"otp", schoolCode, role:"dos"|"teacher", username, recipients:[{phone,message}] }
 *   Admin test SMS   { purpose:"admintest", idToken, recipients:[{phone}] }
 *   Admin top-up     { purpose:"topup", idToken, schoolCode, credits, topupId, note? }
 *   Admin SMS PIN    { purpose:"setpin", idToken, schoolCode }                -> { ok, pin }  (shown once)
 *   Admin cleanup    { purpose:"deleteschool", idToken, schoolCode }          -> wipes wallet + PIN
 *   Admin re-code    { purpose:"movecode", idToken, oldCode, newCode }        -> moves wallet + PIN
 *   School send also needs   smsPin  (6 digits, issued by the admin, stored only as a scrypt hash server-side)
 * Response: { ok:true, sent, failed, failedNumbers, creditsUsed, newBalance? } | { ok:true, newBalance, duplicate? } | { ok:false, error }
 *
 * CREDIT WALLET: schools/{code}/sms/credits in Realtime Database. Database rules make that node
 * read-only for browsers; ONLY this function (Admin SDK) changes it â€” sends, refunds and top-ups.
 *
 * Secrets and settings come from Vercel Environment Variables (see .env.example).
 */
const crypto = require("crypto");
const { promisify } = require("util");
const scrypt = promisify(crypto.scrypt);
const admin = require("firebase-admin");

/* ------------------------------ configuration ------------------------------ */
const AT_USERNAME = process.env.AT_USERNAME;
const AT_API_KEY = process.env.AT_API_KEY;
const AT_SENDER_ID = (process.env.AT_SENDER_ID || "").trim();
const AT_ENDPOINT =
  AT_USERNAME === "sandbox"
    ? "https://api.sandbox.africastalking.com/version1/messaging"
    : "https://api.africastalking.com/version1/messaging";

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || "")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const STRICT_RECIPIENTS = (process.env.STRICT_RECIPIENTS || "true").toLowerCase() !== "false";
const SCHOOL_DAILY_CAP = Number(process.env.SMS_DAILY_CAP) || 5000; // credits per school per day
const MAX_RECIPIENTS = 2000;
const MAX_TOPUP = 100000;         // sanity ceiling for one top-up call
const PIN_MAX_ATTEMPTS = 5;       // wrong-PIN attempts allowed before a school is locked
const PIN_WINDOW_MS = 3600 * 1000;
const PIN_LOCK_MS = 30 * 60 * 1000;
const NO_RECIPIENT_PURPOSES = ["topup", "setpin", "deleteschool", "movecode"]; // admin actions that send nothing
const MAX_MESSAGE_CHARS = 1000;
const CHUNK_SIZE = 100;          // numbers per Africa's Talking call (same message)
const CONCURRENCY = 10;          // parallel Africa's Talking calls
const AT_TIMEOUT_MS = 20000;
const TIME_BUDGET_MS = 50000;    // stop starting new calls after this (function limit is 60s)

const OTP_RE = /^Your EduTrack CBC verification code is \d{6}\. It expires in 10 minutes\. Didn't request this\? Ignore this message\.$/;
const ADMIN_TEST_MESSAGE =
  "This is a test message from EduTrack CBC. If you received this, SMS sending is working correctly.";

/* ------------------------------ firebase ------------------------------ */
function getDb() {
  if (!admin.apps.length) {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw) throw new Error("FIREBASE_SERVICE_ACCOUNT is not set");
    admin.initializeApp({
      credential: admin.credential.cert(JSON.parse(raw)),
      databaseURL:
        process.env.FIREBASE_DATABASE_URL ||
        "https://markbook-45fc1-default-rtdb.firebaseio.com",
    });
  }
  return admin.database();
}

/* ------------------------------ helpers ------------------------------ */
// Mirrors normalizePhone() / isValidSmsPhone() / smsSegments() in index.html exactly,
// so the server bills what the app previewed.
function normalizePhone(raw) {
  let p = String(raw || "").replace(/[^\d+]/g, "");
  if (!p) return "";
  if (p.startsWith("00")) p = "+" + p.slice(2);
  if (p.startsWith("+")) return p;
  if (p.startsWith("0")) return "+254" + p.slice(1);
  if (p.startsWith("254")) return "+" + p;
  if (/^[71]\d{8}$/.test(p)) return "+254" + p;
  return p;
}
function isValidPhone(n) {
  if (!n || !n.startsWith("+")) return false;
  if (n.startsWith("+254")) return /^\+254[71]\d{8}$/.test(n);
  return /^\+\d{8,15}$/.test(n);
}
const GSM7_BASIC =
  "@Â£$Â¥Ã¨Ã©Ã¹Ã¬Ã²Ã‡\nÃ˜Ã¸\rÃ…Ã¥Î”_Î¦Î“Î›Î©Î Î¨Î£Î˜ÎžÃ†Ã¦ÃŸÃ‰ !\"#Â¤%&'()*+,-./0123456789:;<=>?Â¡ABCDEFGHIJKLMNOPQRSTUVWXYZÃ„Ã–Ã‘ÃœÂ§Â¿abcdefghijklmnopqrstuvwxyzÃ¤Ã¶Ã±Ã¼Ã ";
const GSM7_EXT = "^{}\\[~]|â‚¬";
function segments(text) {
  text = text || "";
  let units = 0, unicode = false;
  for (const ch of text) {
    if (GSM7_BASIC.includes(ch)) units += 1;
    else if (GSM7_EXT.includes(ch)) units += 2;
    else { unicode = true; break; }
  }
  if (unicode) {
    units = Array.from(text).reduce((n, ch) => n + (ch.codePointAt(0) > 0xffff ? 2 : 1), 0);
    return units <= 70 ? 1 : Math.ceil(units / 67);
  }
  return units <= 160 ? 1 : Math.ceil(units / 153);
}
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 24);
function clientIp(req) {
  const xff = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return xff || (req.socket && req.socket.remoteAddress) || "unknown";
}
function eatDay() { return new Date(Date.now() + 3 * 3600 * 1000).toISOString().slice(0, 10).replace(/-/g, ""); }
function fail(res, code, error) { return res.status(code).json({ ok: false, error }); }
const creditPath = (code) => `schools/${code}/sms/credits`;   // server-owned wallet (clients: read-only via rules)
/* ---- SMS PIN: the secret that lets a school's staff spend that school's credit ----
   Stored ONLY as a salted scrypt hash under smsMeta/pins/{code}, which no browser can read
   (there is no client rule for smsMeta). It never appears in the synced school data, so someone
   who can read that data - e.g. anyone who knows the school code - still cannot send. */
async function hashPin(pin, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const hash = await scrypt(String(pin), salt, 32);
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}
async function pinMatches(pin, rec) {
  const { hash } = await hashPin(pin, rec.salt);
  const a = Buffer.from(hash, "hex"), b = Buffer.from(String(rec.hash), "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
// Atomically CLAIMS an attempt before the PIN is checked, so parallel guesses can't out-run the limit.
async function claimPinAttempt(db, code) {
  const ref = db.ref(`smsMeta/pinfail/${code}`);
  const now = Date.now();
  let ok = false, waitMs = 0;
  await ref.transaction((cur) => {
    ok = false; waitMs = 0;
    cur = cur && typeof cur === "object" ? cur : {};
    if (cur.until && now < cur.until) { waitMs = cur.until - now; return; } // locked -> abort
    const stale = !cur.t || now - cur.t > PIN_WINDOW_MS || (cur.until && now >= cur.until);
    const c = (stale ? 0 : cur.c || 0) + 1;
    ok = true;
    return c >= PIN_MAX_ATTEMPTS ? { c: 0, t: now, until: now + PIN_LOCK_MS } : { c, t: stale ? now : cur.t };
  });
  return { ok, waitMs };
}
async function checkSmsPin(db, code, pin) {
  const rec = (await db.ref(`smsMeta/pins/${code}`).once("value")).val();
  if (!rec || !rec.hash || !rec.salt)
    return { status: 403, error: "SMS sending isn't activated for this school yet. Ask the platform administrator for your SMS PIN." };
  if (typeof pin !== "string" || !/^\d{6}$/.test(pin)) return { status: 403, error: "Enter your 6-digit SMS PIN." };
  const claim = await claimPinAttempt(db, code);
  if (!claim.ok)
    return { status: 429, error: `Too many wrong PIN attempts. Try again in ${Math.max(1, Math.ceil(claim.waitMs / 60000))} minute(s), or ask the administrator.` };
  if (!(await pinMatches(pin, rec))) return { status: 403, error: "Incorrect SMS PIN." };
  await db.ref(`smsMeta/pinfail/${code}`).remove().catch(() => {});
  return { ok: true };
}
// Verifies a Firebase ID token and that its email is one of ADMIN_EMAILS.
// Returns { decoded } on success or { error:[status, message] } on failure.
async function checkAdmin(idToken) {
  if (!ADMIN_EMAILS.length) return { error: [500, "ADMIN_EMAILS is not set on the server."] };
  if (typeof idToken !== "string" || !idToken) return { error: [401, "Sign in with your cloud admin account first."] };
  let decoded;
  try { decoded = await admin.auth().verifyIdToken(idToken); } catch (e) { return { error: [401, "Admin sign-in expired. Sign in again."] }; }
  if (!decoded.email || !ADMIN_EMAILS.includes(String(decoded.email).toLowerCase())) return { error: [403, "Not allowed"] };
  return { decoded };
}

/* ------------------------------ rate limit (persistent, shared across instances) ------------------------------ */
async function allow(db, key, limit, windowMs) {
  const ref = db.ref("smsMeta/rate/" + key);
  const now = Date.now();
  let ok = false;
  await ref.transaction((cur) => {
    ok = false;
    if (!cur || typeof cur !== "object" || now > cur.reset) { ok = true; return { c: 1, reset: now + windowMs }; }
    if (cur.c >= limit) return; // abort
    ok = true;
    return { c: cur.c + 1, reset: cur.reset };
  });
  return ok;
}

/* ------------------------------ credit accounting (atomic) ------------------------------ */
// Firebase may first run a transaction against a null local guess; returning a value there makes
// the server reject it and re-run with the real number. Returning undefined would abort wrongly.
async function reserve(db, path, amount, cap) {
  const ref = db.ref(path);
  let ok = false;
  const tx = await ref.transaction((cur) => {
    ok = false;
    if (cur === null) return 0;
    if (typeof cur !== "number" || cur < amount) return;
    ok = true;
    return cur - amount;
  });
  return { ok: tx.committed && ok, value: Number(tx.snapshot.val()) || 0 };
}
async function reserveDaily(db, code, amount) {
  const ref = db.ref(`smsMeta/daily/${code}/${eatDay()}`);
  let ok = false;
  const tx = await ref.transaction((cur) => {
    ok = false;
    const used = typeof cur === "number" ? cur : 0;
    if (used + amount > SCHOOL_DAILY_CAP) return;
    ok = true;
    return used + amount;
  });
  return tx.committed && ok;
}
async function addBack(db, path, amount) {
  if (amount <= 0) return null;
  const tx = await db.ref(path).transaction((cur) => (typeof cur === "number" ? cur : 0) + amount);
  return Number(tx.snapshot.val()) || 0;
}
async function releaseDaily(db, code, amount) {
  if (amount <= 0) return;
  await db.ref(`smsMeta/daily/${code}/${eatDay()}`).transaction((cur) => Math.max(0, (typeof cur === "number" ? cur : 0) - amount));
}

/* ------------------------------ Africa's Talking ------------------------------ */
async function sendGroup(numbers, message) {
  const results = {};
  try {
    const params = { username: AT_USERNAME, to: numbers.join(","), message };
    if (AT_SENDER_ID && AT_USERNAME !== "sandbox") params.from = AT_SENDER_ID;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), AT_TIMEOUT_MS);
    let r;
    try {
      r = await fetch(AT_ENDPOINT, {
        method: "POST",
        headers: { apiKey: AT_API_KEY, Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(params),
        signal: ctrl.signal,
      });
    } finally { clearTimeout(timer); }
    const text = await r.text();
    let data = {};
    try { data = JSON.parse(text); } catch (e) { /* non-JSON error page */ }
    console.log("AT raw response", r.status, text.slice(0, 500));
    if (!r.ok && !(data.SMSMessageData)) console.error("Africa's Talking HTTP", r.status, text.slice(0, 200));
    const recips = (data.SMSMessageData && data.SMSMessageData.Recipients) || [];
    recips.forEach((x) => { results[normalizePhone(x.number)] = { ok: x.status === "Success", status: x.status }; });
  } catch (e) {
    console.error("sendGroup error", e && e.message);
  }
  numbers.forEach((n) => { if (!results[n]) results[n] = { ok: false, status: "No response from carrier" }; });
  return results;
}

async function sendAll(recipients) {
  const byMessage = {};
  recipients.forEach((r) => (byMessage[r.message] = byMessage[r.message] || new Set()).add(r.phone));
  const tasks = [];
  Object.keys(byMessage).forEach((message) => {
    const nums = Array.from(byMessage[message]);
    for (let i = 0; i < nums.length; i += CHUNK_SIZE) tasks.push({ message, numbers: nums.slice(i, i + CHUNK_SIZE) });
  });
  const deadline = Date.now() + TIME_BUDGET_MS;
  let sent = 0, failed = 0, creditsUsed = 0, notAttempted = 0;
  const failedNumbers = [];
  let next = 0;
  async function worker() {
    while (next < tasks.length) {
      const t = tasks[next++];
      if (Date.now() > deadline) {
        notAttempted += t.numbers.length; failed += t.numbers.length; failedNumbers.push(...t.numbers);
        continue;
      }
      const segs = segments(t.message);
      const results = await sendGroup(t.numbers, t.message);
      t.numbers.forEach((n) => {
        if (results[n].ok) { sent++; creditsUsed += segs; } else { failed++; failedNumbers.push(n); }
      });
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, tasks.length) }, worker));
  return { sent, failed, failedNumbers, creditsUsed, notAttempted };
}

/* ------------------------------ handler ------------------------------ */
function applyCors(req, res) {
  const allowed = (process.env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const origin = req.headers.origin;
  if (!allowed.length) res.setHeader("Access-Control-Allow-Origin", "*");
  else if (origin && allowed.includes(origin)) { res.setHeader("Access-Control-Allow-Origin", origin); res.setHeader("Vary", "Origin"); }
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  return !allowed.length || !origin || allowed.includes(origin);
}
const asArray = (v) => (Array.isArray(v) ? v : v && typeof v === "object" ? Object.values(v) : []);

module.exports = async (req, res) => {
  const originOk = applyCors(req, res);
  if (req.method === "OPTIONS") return res.status(originOk ? 204 : 403).end();
  if (req.method !== "POST") return fail(res, 405, "POST only");
  if (!originOk) return fail(res, 403, "Origin not allowed");
  if (!AT_USERNAME || !AT_API_KEY) return fail(res, 500, "SMS is not configured on the server yet.");

  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch (e) { body = {}; } }
  body = body || {};
  const { schoolCode, purpose, role, username, idToken } = body;

  // ---- validate & normalise recipients (every mode except a top-up, which sends nothing) ----
  const recipients = [];
  if (!NO_RECIPIENT_PURPOSES.includes(purpose)) {
    if (!Array.isArray(body.recipients) || body.recipients.length === 0) return fail(res, 400, "No recipients supplied");
    if (body.recipients.length > MAX_RECIPIENTS) return fail(res, 400, "Too many recipients in one request");
    for (const r of body.recipients) {
      if (!r || typeof r.phone !== "string") return fail(res, 400, "Every recipient needs a phone and a message");
      const phone = normalizePhone(r.phone);
      if (!isValidPhone(phone)) return fail(res, 400, "Invalid phone number: " + r.phone);
      const message = purpose === "admintest" ? ADMIN_TEST_MESSAGE : r.message;
      if (typeof message !== "string" || !message.trim()) return fail(res, 400, "Every recipient needs a phone and a message");
      if (message.length > MAX_MESSAGE_CHARS) return fail(res, 400, "Message too long");
      recipients.push({ phone, message });
    }
  }

  let db;
  try {
    db = getDb();
    const ip = sha(clientIp(req));
    if (!(await allow(db, "ip_" + ip, purpose ? 30 : 200, 3600 * 1000)))
      return fail(res, 429, "Too many requests from this network. Try again later.");

    /* ===== Password-reset code ===== */
    if (purpose === "otp") {
      if (recipients.length !== 1) return fail(res, 400, "One recipient only");
      if (!OTP_RE.test(recipients[0].message)) return fail(res, 400, "Message not allowed");
      if (!validCode(schoolCode) || !["dos", "teacher"].includes(role) || typeof username !== "string" || !username)
        return fail(res, 400, "Invalid request");
      const snap = await db.ref(`schools/${schoolCode}/data/${role === "dos" ? "dos" : "teachers"}`).once("value");
      const rec = asArray(snap.val()).find((x) => x && x.username === username);
      if (!rec || !rec.phone || normalizePhone(rec.phone) !== recipients[0].phone)
        return fail(res, 403, "Not allowed");
      const p = recipients[0].phone;
      if (!(await allow(db, "otpphone_" + sha(p), 5, 3600 * 1000)) ||
          !(await allow(db, "otpuser_" + sha(schoolCode + "|" + role + "|" + username), 5, 3600 * 1000)))
        return fail(res, 429, "Too many code requests. Try again in an hour.");
      const result = await sendAll(recipients);
      return res.json({ ok: true, ...result, creditsUsed: 0 });
    }

    /* ===== Admin: issue / reset a school's SMS PIN (shown once, stored only as a hash) ===== */
    if (purpose === "setpin") {
      const chk = await checkAdmin(idToken);
      if (chk.error) return fail(res, chk.error[0], chk.error[1]);
      if (!validCode(schoolCode)) return fail(res, 400, "A valid schoolCode is required");
      if (!(await allow(db, "adminops_" + chk.decoded.uid, 60, 3600 * 1000))) return fail(res, 429, "Too many admin actions this hour. Try again later.");
      if (!(await db.ref(`schools/${schoolCode}/data/name`).once("value")).exists()) return fail(res, 404, "Unknown school code");
      const pin = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
      const h = await hashPin(pin);
      await db.ref(`smsMeta/pins/${schoolCode}`).set({ ...h, ts: Date.now(), by: String(chk.decoded.email).toLowerCase() });
      await db.ref(`smsMeta/pinfail/${schoolCode}`).remove();
      await db.ref(`schools/${schoolCode}/sms/pinSet`).set(Date.now()); // non-secret flag so the apps can show "activated"
      return res.json({ ok: true, pin });
    }

    /* ===== Admin: school deleted -> wipe its wallet + PIN so a re-used code can't inherit them ===== */
    if (purpose === "deleteschool") {
      const chk = await checkAdmin(idToken);
      if (chk.error) return fail(res, chk.error[0], chk.error[1]);
      if (!validCode(schoolCode)) return fail(res, 400, "A valid schoolCode is required");
      const discarded = Number((await db.ref(creditPath(schoolCode)).once("value")).val()) || 0;
      await Promise.all([
        db.ref(`schools/${schoolCode}/sms`).remove(),
        db.ref(`smsMeta/pins/${schoolCode}`).remove(),
        db.ref(`smsMeta/pinfail/${schoolCode}`).remove(),
        db.ref(`smsMeta/daily/${schoolCode}`).remove(),
      ]);
      return res.json({ ok: true, discardedCredits: discarded }); // topups/audit ledgers are deliberately kept
    }

    /* ===== Admin: school code changed -> carry the wallet + PIN across ===== */
    if (purpose === "movecode") {
      const chk = await checkAdmin(idToken);
      if (chk.error) return fail(res, chk.error[0], chk.error[1]);
      const { oldCode, newCode } = body;
      if (!validCode(oldCode) || !validCode(newCode) || oldCode === newCode) return fail(res, 400, "Two different valid school codes are required");
      const [tSms, tPin, sSms, sPin] = await Promise.all([
        db.ref(`schools/${newCode}/sms`).once("value"), db.ref(`smsMeta/pins/${newCode}`).once("value"),
        db.ref(`schools/${oldCode}/sms`).once("value"), db.ref(`smsMeta/pins/${oldCode}`).once("value"),
      ]);
      if (tSms.exists() || tPin.exists())
        return fail(res, 409, "The new code already has an SMS wallet or PIN on the server (left over from an earlier school). Remove schools/" + newCode + "/sms and smsMeta/pins/" + newCode + " in the Firebase console, then try again.");
      if (sSms.exists()) await db.ref(`schools/${newCode}/sms`).set(sSms.val());
      if (sPin.exists()) await db.ref(`smsMeta/pins/${newCode}`).set(sPin.val());
      await Promise.all([
        db.ref(`schools/${oldCode}/sms`).remove(), db.ref(`smsMeta/pins/${oldCode}`).remove(),
        db.ref(`smsMeta/pinfail/${oldCode}`).remove(), db.ref(`smsMeta/daily/${oldCode}`).remove(),
      ]);
      return res.json({ ok: true, credits: Number((sSms.val() || {}).credits) || 0, pinMoved: sPin.exists() });
    }

    /* ===== Admin top-up (the ONLY way credit is ever added) ===== */
    if (purpose === "topup") {
      const chk = await checkAdmin(idToken);
      if (chk.error) return fail(res, chk.error[0], chk.error[1]);
      const decoded = chk.decoded;
      const credits = body.credits, topupId = body.topupId;
      if (!validCode(schoolCode)) return fail(res, 400, "A valid schoolCode is required");
      if (!Number.isInteger(credits) || credits < 1 || credits > MAX_TOPUP) return fail(res, 400, `Credits must be a whole number between 1 and ${MAX_TOPUP}`);
      if (typeof topupId !== "string" || !/^[A-Za-z0-9_-]{6,64}$/.test(topupId)) return fail(res, 400, "A valid topupId is required");
      if (!(await allow(db, "admintopup_" + decoded.uid, 60, 3600 * 1000))) return fail(res, 429, "Too many top-ups this hour. Try again later.");
      const nameSnap = await db.ref(`schools/${schoolCode}/data/name`).once("value");
      if (!nameSnap.exists()) return fail(res, 404, "Unknown school code");

      // Idempotency: the first call with this topupId claims it; repeats just report the balance.
      const claimRef = db.ref(`smsMeta/topups/${schoolCode}/${topupId}`);
      let claimed = false;
      await claimRef.transaction((cur) => {
        claimed = false;
        if (cur !== null && cur !== undefined) return; // already applied -> abort
        claimed = true;
        return { ts: Date.now(), credits, by: String(decoded.email).toLowerCase(), note: String(body.note || "").slice(0, 200) };
      });
      if (!claimed) {
        const cur = await db.ref(creditPath(schoolCode)).once("value");
        return res.json({ ok: true, duplicate: true, newBalance: Number(cur.val()) || 0 });
      }
      try {
        const newBalance = await addBack(db, creditPath(schoolCode), credits);
        return res.json({ ok: true, newBalance });
      } catch (err) {
        await claimRef.remove().catch(() => {}); // let the admin retry safely
        throw err;
      }
    }

    /* ===== Admin test SMS ===== */
    if (purpose === "admintest") {
      const chk = await checkAdmin(idToken);
      if (chk.error) return fail(res, chk.error[0], chk.error[1]);
      const decoded = chk.decoded;
      if (recipients.length !== 1) return fail(res, 400, "One recipient only");
      if (!(await allow(db, "admintest_" + decoded.uid, 10, 3600 * 1000))) return fail(res, 429, "Too many test messages. Try again later.");
      const result = await sendAll(recipients);
      return res.json({ ok: true, ...result, creditsUsed: 0 });
    }

    if (purpose) return fail(res, 400, "Unknown purpose");
    if (body.test) return fail(res, 400, "This app version is out of date. Reload the page and try again.");

    /* ===== School send (billed) ===== */
    if (!validCode(schoolCode)) return fail(res, 400, "A valid schoolCode is required");
    const base = `schools/${schoolCode}/data`;
    const studentsSnap = await db.ref(base + "/students").once("value");
    if (!studentsSnap.exists()) return fail(res, 404, "Unknown school code");

    // The school's SMS PIN (issued by the platform admin, hash-only on the server) authorises spending.
    const pinCheck = await checkSmsPin(db, schoolCode, body.smsPin);
    if (!pinCheck.ok) return fail(res, pinCheck.status, pinCheck.error);

    if (STRICT_RECIPIENTS) {
      const allowedPhones = new Set(asArray(studentsSnap.val()).map((s) => s && normalizePhone(s.parentPhone)).filter(Boolean));
      const unknown = new Set(recipients.filter((r) => !allowedPhones.has(r.phone)).map((r) => r.phone));
      if (unknown.size)
        return fail(res, 400, `${unknown.size} number(s) don't match learner records saved in the cloud yet. Wait a moment for sync to finish, then try again.`);
    }

    const needed = recipients.reduce((n, r) => n + segments(r.message), 0);
    if (!(await reserveDaily(db, schoolCode, needed)))
      return fail(res, 429, `Daily SMS limit reached for this school (${SCHOOL_DAILY_CAP} credits/day). Try again tomorrow or contact the administrator.`);
    const wallet = creditPath(schoolCode);
    const held = await reserve(db, wallet, needed);
    if (!held.ok) {
      await releaseDaily(db, schoolCode, needed);
      return fail(res, 400, `Not enough credit: need ${needed}, have ${held.value}`);
    }

    let result;
    try {
      result = await sendAll(recipients);
    } catch (err) {
      await addBack(db, wallet, needed);
      await releaseDaily(db, schoolCode, needed);
      throw err;
    }
    const refund = needed - result.creditsUsed;
    let newBalance = held.value;
    if (refund > 0) {
      const b = await addBack(db, wallet, refund);
      if (b !== null) newBalance = b;
      await releaseDaily(db, schoolCode, refund);
    }
    try {
      await db.ref(`smsMeta/audit/${schoolCode}`).push({
        ts: Date.now(), recipients: recipients.length, sent: result.sent, failed: result.failed, credits: result.creditsUsed,
      });
    } catch (e) { /* audit is best-effort */ }
    return res.json({ ok: true, ...result, newBalance });
  } catch (err) {
    console.error("sendSms failed", err);
    return fail(res, 500, "Server error: " + (err.message || err));
  }
};

function validCode(c) { return typeof c === "string" && c.length > 0 && c.length <= 64 && !/[.#$\[\]\/]/.test(c); }
