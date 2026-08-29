require('dotenv').config();
const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { UAParser } = require('ua-parser-js');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';
const WEAK_SECRET_VALUES = new Set([
  'ncmsoft-admin-2025',
  'ncmsoft-demo-secret-2025',
  'dev-admin-key-change-me',
  'change-me',
  'changeme',
  'change-this-to-a-long-random-secret',
  'change-this-to-the-same-long-random-secret-as-backend',
]);

function readSecret(name, { requiredInProduction = false, devFallback = '' } = {}) {
  const raw = String(process.env[name] || '').trim();
  const value = raw || (!IS_PRODUCTION ? devFallback : '');
  if (IS_PRODUCTION && requiredInProduction && !value) {
    throw new Error(`${name} production ortaminda zorunludur.`);
  }
  if (IS_PRODUCTION && value && WEAK_SECRET_VALUES.has(value)) {
    throw new Error(`${name} ornek/varsayilan degerle production ortaminda kullanilamaz.`);
  }
  if (!raw && devFallback) {
    console.warn(`[Config] ${name} tanimli degil; yalnizca lokal gelistirme icin gecici deger kullaniliyor.`);
  }
  return value;
}

const ADMIN_KEY = readSecret('ADMIN_KEY', {
  requiredInProduction: true,
  devFallback: 'dev-admin-key-change-me',
});
const DEMO_URL = process.env.DEMO_URL || 'http://portal.ncmteknoloji.com';
const BACKEND_INTERNAL_URL = process.env.BACKEND_INTERNAL_URL || 'http://localhost:3000';
const DEMO_PROVISION_KEY = readSecret('DEMO_PROVISION_KEY');
const ALLOW_ADMIN_KEY_QUERY =
  !IS_PRODUCTION && String(process.env.ALLOW_ADMIN_KEY_QUERY || '').toLowerCase() === 'true';

// Demo talep bildirimlerinin gideceği adres (talep edildiği gibi Taner'e).
const DEMO_NOTIFY_EMAIL = process.env.DEMO_NOTIFY_EMAIL || process.env.ADMIN_EMAIL || 'taner.dambasan@gmail.com';
// Doğrulama kodu ve kurulum jetonu geçerlilik süreleri (dakika).
const CODE_TTL_MINUTES = parseInt(process.env.VERIFY_CODE_TTL_MINUTES || '15', 10);
const ONBOARD_TTL_MINUTES = parseInt(process.env.ONBOARD_TOKEN_TTL_MINUTES || '60', 10);
const MAX_CODE_ATTEMPTS = parseInt(process.env.VERIFY_CODE_MAX_ATTEMPTS || '5', 10);

// Ensure data directory exists
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'ncmsoft.db');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── DATABASE ─────────────────────────────────────────────
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS visitors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT,
    user_agent      TEXT,
    browser_name    TEXT,
    browser_version TEXT,
    os_name         TEXT,
    os_version      TEXT,
    device_type     TEXT,
    referrer        TEXT,
    page            TEXT,
    screen_res      TEXT,
    language        TEXT,
    timezone        TEXT,
    session_id      TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS registrations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name   TEXT NOT NULL,
    last_name    TEXT NOT NULL,
    email        TEXT NOT NULL,
    phone        TEXT,
    company      TEXT,
    verify_token TEXT UNIQUE,
    verified     INTEGER DEFAULT 0,
    verified_at  DATETIME,
    ip           TEXT,
    user_agent   TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ── Şema göçü: kod doğrulama + kurulum sihirbazı kolonları ────────────────
// node:sqlite ALTER TABLE ... ADD COLUMN IF NOT EXISTS desteklemez; PRAGMA ile
// mevcut kolonları kontrol edip eksik olanları ekliyoruz.
function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    console.log(`[DB] ${table}.${column} kolonu eklendi.`);
  }
}

ensureColumn('registrations', 'verify_code', 'TEXT');
ensureColumn('registrations', 'code_expires_at', 'DATETIME');
ensureColumn('registrations', 'code_attempts', 'INTEGER DEFAULT 0');
ensureColumn('registrations', 'code_sent_at', 'DATETIME');
ensureColumn('registrations', 'onboard_token', 'TEXT');
ensureColumn('registrations', 'onboard_expires_at', 'DATETIME');
ensureColumn('registrations', 'provisioned', 'INTEGER DEFAULT 0');
ensureColumn('registrations', 'provisioned_at', 'DATETIME');
ensureColumn('registrations', 'admin_email', 'TEXT');

// ── MIDDLEWARE ────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
}));

const STATIC_DENY_SEGMENTS = new Set(['data', 'node_modules', '.git']);
const STATIC_DENY_FILES = new Set([
  'server.js',
  'sms.js',
  'test-sms.js',
  'package.json',
  'package-lock.json',
  'README.md',
  '.env',
  '.env.example',
  '.gitignore',
]);

function rejectSensitiveStaticFiles(req, res, next) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  let pathname = '/';
  try {
    pathname = decodeURIComponent(new URL(req.originalUrl, BASE_URL).pathname).replace(/\\/g, '/');
  } catch {
    pathname = String(req.path || '/').replace(/\\/g, '/');
  }

  const segments = pathname.split('/').filter(Boolean);
  const first = segments[0] || '';
  const leaf = segments[segments.length - 1] || '';
  if (
    first === 'api' ||
    (!segments.length && pathname === '/')
  ) {
    return next();
  }

  if (
    STATIC_DENY_SEGMENTS.has(first) ||
    STATIC_DENY_FILES.has(leaf) ||
    segments.some((segment) => segment.startsWith('.'))
  ) {
    return res.status(404).send('Not found');
  }

  return next();
}

app.use(rejectSensitiveStaticFiles);
app.use(express.static(path.join(__dirname), {
  dotfiles: 'deny',
  index: 'index.html',
  extensions: ['html'],
}));

// ── HELPERS ───────────────────────────────────────────────
function getRealIP(req) {
  return (
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

async function sendEmail({ to, subject, html }) {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER) {
    console.warn('[Mail] SMTP ayarları eksik — .env dosyasını kontrol edin.');
    return;
  }
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  return transporter.sendMail({
    from: process.env.SMTP_FROM || `"NCMSoft" <${process.env.SMTP_USER}>`,
    to,
    subject,
    html,
  });
}

// ── SMS ALTYAPISI ─────────────────────────────────────────────────────────
// Gönderim katmanı ayrı modülde (sms.js). test-sms.js ile de paylaşılır.
const { sendSms } = require('./sms');

// ── HELPERS: doğrulama kodu / zaman ────────────────────────────────────────
function genCode() {
  // 6 haneli, baştan sıfır içerebilen kod.
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function minutesFromNow(minutes) {
  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}

function isExpired(iso) {
  if (!iso) return true;
  const t = new Date(iso).getTime();
  return !Number.isFinite(t) || Date.now() > t;
}

function timingSafeEqualText(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'] || (ALLOW_ADMIN_KEY_QUERY ? req.query.key : '');
  if (!key || !timingSafeEqualText(key, ADMIN_KEY)) {
    return res.status(401).json({ error: 'Yetkisiz erişim.' });
  }
  next();
}

const rateBuckets = new Map();

function rateLimit(name, { windowMs, max, keyFn }) {
  return (req, res, next) => {
    const key = `${name}:${keyFn(req) || getRealIP(req)}`;
    const now = Date.now();
    const current = rateBuckets.get(key);
    if (!current || current.resetAt <= now) {
      rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (current.count >= max) {
      const retryAfter = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ ok: false, error: 'Çok fazla deneme yapıldı. Lütfen biraz sonra tekrar deneyin.' });
    }
    current.count += 1;
    return next();
  };
}

function emailOrIpKey(req) {
  const email = String(req.body?.email || req.query?.email || '').trim().toLowerCase();
  return email || getRealIP(req);
}

// ── HELPERS: Backend API çağrısı ──────────────────────────────────────────
function callBackendApi(path, method, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(BACKEND_INTERNAL_URL);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;
    const bodyStr = JSON.stringify(body);

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
        ...headers,
      },
    };

    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

// ── API: VISITOR TRACKING ─────────────────────────────────
app.post('/api/track', rateLimit('track', {
  windowMs: 60 * 1000,
  max: 180,
  keyFn: getRealIP,
}), (req, res) => {
  try {
    const ip = getRealIP(req);
    const ua = req.headers['user-agent'] || '';
    const parser = new UAParser(ua);
    const r = parser.getResult();

    const { referrer = '', page = '', screen_res = '', language = '', timezone = '', session_id = '' } = req.body;

    db.prepare(`
      INSERT INTO visitors (ip, user_agent, browser_name, browser_version, os_name, os_version,
        device_type, referrer, page, screen_res, language, timezone, session_id)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(
      ip, ua,
      r.browser.name || '', r.browser.version || '',
      r.os.name || '', r.os.version || '',
      r.device.type || 'desktop',
      referrer, page, screen_res, language, timezone, session_id
    );
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// ── API: REGISTER ─────────────────────────────────────────
app.post('/api/register', rateLimit('register', {
  windowMs: 15 * 60 * 1000,
  max: 8,
  keyFn: getRealIP,
}), async (req, res) => {
  const { first_name, last_name, email, phone, company } = req.body || {};

  if (!first_name?.trim() || !last_name?.trim() || !email?.trim()) {
    return res.status(400).json({ ok: false, error: 'Ad, soyad ve e-posta zorunludur.' });
  }

  const emailLower = email.trim().toLowerCase();
  const ip = getRealIP(req);
  const ua = req.headers['user-agent'] || '';
  const cleanPhone = (phone || '').trim();

  try {
    const code = genCode();
    const codeExpires = minutesFromNow(CODE_TTL_MINUTES);
    const existing = db.prepare('SELECT * FROM registrations WHERE email = ?').get(emailLower);

    if (existing && existing.provisioned) {
      return res.json({
        ok: true,
        alreadyProvisioned: true,
        pendingApproval: true,
        message: 'Bu e-posta için demo şirket kurulumu zaten oluşturulmuş ve yönetici onayı bekliyor.',
      });
    }

    if (existing) {
      // Mevcut kayıt → yeni kod üret, bilgileri güncelle.
      db.prepare(`
        UPDATE registrations
        SET first_name = ?, last_name = ?, phone = ?, company = ?,
            verify_code = ?, code_expires_at = ?, code_attempts = 0,
            code_sent_at = CURRENT_TIMESTAMP, verified = 0
        WHERE id = ?
      `).run(first_name.trim(), last_name.trim(), cleanPhone, company?.trim() || '', code, codeExpires, existing.id);
    } else {
      const token = uuidv4();
      db.prepare(`
        INSERT INTO registrations
          (first_name, last_name, email, phone, company, verify_token, ip, user_agent,
           verify_code, code_expires_at, code_attempts, code_sent_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
      `).run(
        first_name.trim(), last_name.trim(), emailLower, cleanPhone, company?.trim() || '',
        token, ip, ua, code, codeExpires
      );
    }

    // ── Kullanıcıya doğrulama kodu (e-posta) ──────────────────────────────
    await sendEmail({
      to: emailLower,
      subject: `NCMSoft Doğrulama Kodunuz: ${code}`,
      html: verifyCodeEmailHtml(first_name.trim(), code, CODE_TTL_MINUTES),
    });

    // ── Kullanıcıya doğrulama kodu (SMS altyapısı) ────────────────────────
    if (cleanPhone) {
      sendSms({
        to: cleanPhone,
        message: `NCMSoft demo dogrulama kodunuz: ${code} (${CODE_TTL_MINUTES} dk gecerli)`,
      }).catch((e) => console.error('[SMS] register:', e.message));
    }

    // ── Admin bildirim (talep edildiği gibi Taner'e) ──────────────────────
    sendEmail({
      to: DEMO_NOTIFY_EMAIL,
      subject: `[NCMSoft] Yeni Demo Talebi: ${first_name} ${last_name} — ${company || 'Firma belirtilmedi'}`,
      html: adminNotifyHtml({ first_name, last_name, email: emailLower, phone: cleanPhone, company, ip }),
    }).catch(console.error);

    res.json({
      ok: true,
      email: emailLower,
      next: `/verify.html?email=${encodeURIComponent(emailLower)}`,
      message: 'Doğrulama kodu e-posta adresinize gönderildi.',
    });
  } catch (err) {
    console.error('[Register]', err);
    res.status(500).json({ ok: false, error: 'Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.' });
  }
});

// ── API: VERIFY CODE (kod ile doğrulama) ──────────────────────────────────
app.post('/api/verify-code', rateLimit('verify-code', {
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyFn: emailOrIpKey,
}), async (req, res) => {
  const { email, code } = req.body || {};
  const emailLower = String(email || '').trim().toLowerCase();
  const codeStr = String(code || '').trim();

  if (!emailLower || !/^\d{6}$/.test(codeStr)) {
    return res.status(400).json({ ok: false, error: 'E-posta ve 6 haneli kod zorunludur.' });
  }

  const reg = db.prepare('SELECT * FROM registrations WHERE email = ?').get(emailLower);
  if (!reg) {
    return res.status(404).json({ ok: false, error: 'Kayıt bulunamadı. Lütfen yeniden talep oluşturun.' });
  }
  if (reg.provisioned) {
    return res.json({
      ok: true,
      alreadyProvisioned: true,
      pendingApproval: true,
      message: 'Demo şirket kurulumu oluşturulmuş ve yönetici onayı bekliyor.',
    });
  }
  if ((reg.code_attempts || 0) >= MAX_CODE_ATTEMPTS) {
    return res.status(429).json({ ok: false, error: 'Çok fazla hatalı deneme. Lütfen yeni kod isteyin.' });
  }
  if (!reg.verify_code || isExpired(reg.code_expires_at)) {
    return res.status(410).json({ ok: false, error: 'Kodun süresi dolmuş. Lütfen yeni kod isteyin.', expired: true });
  }
  if (codeStr !== reg.verify_code) {
    db.prepare('UPDATE registrations SET code_attempts = code_attempts + 1 WHERE id = ?').run(reg.id);
    const left = Math.max(0, MAX_CODE_ATTEMPTS - (reg.code_attempts + 1));
    return res.status(401).json({ ok: false, error: `Kod hatalı. Kalan deneme: ${left}.`, attemptsLeft: left });
  }

  // ── Başarılı → kurulum jetonu üret ────────────────────────────────────
  const onboardToken = uuidv4();
  db.prepare(`
    UPDATE registrations
    SET verified = 1, verified_at = CURRENT_TIMESTAMP,
        verify_code = NULL, onboard_token = ?, onboard_expires_at = ?
    WHERE id = ?
  `).run(onboardToken, minutesFromNow(ONBOARD_TTL_MINUTES), reg.id);

  res.json({
    ok: true,
    onboardToken,
    prefill: {
      first_name: reg.first_name,
      last_name: reg.last_name,
      email: reg.email,
      phone: reg.phone,
      company: reg.company,
    },
    next: `/onboard.html?token=${onboardToken}&email=${encodeURIComponent(emailLower)}`,
  });
});

// ── API: RESEND CODE ──────────────────────────────────────────────────────
app.post('/api/resend-code', rateLimit('resend-code', {
  windowMs: 60 * 60 * 1000,
  max: 6,
  keyFn: emailOrIpKey,
}), async (req, res) => {
  const emailLower = String(req.body?.email || '').trim().toLowerCase();
  if (!emailLower) return res.status(400).json({ ok: false, error: 'E-posta zorunludur.' });

  const reg = db.prepare('SELECT * FROM registrations WHERE email = ?').get(emailLower);
  if (!reg) return res.status(404).json({ ok: false, error: 'Kayıt bulunamadı.' });
  if (reg.provisioned) {
    return res.json({
      ok: true,
      alreadyProvisioned: true,
      pendingApproval: true,
      message: 'Demo şirket kurulumu oluşturulmuş ve yönetici onayı bekliyor.',
    });
  }

  // Basit hız sınırı: son gönderimden bu yana en az 30 sn.
  if (reg.code_sent_at && Date.now() - new Date(reg.code_sent_at + 'Z').getTime() < 30 * 1000) {
    return res.status(429).json({ ok: false, error: 'Lütfen yeni kod istemeden önce birkaç saniye bekleyin.' });
  }

  const code = genCode();
  db.prepare(`
    UPDATE registrations
    SET verify_code = ?, code_expires_at = ?, code_attempts = 0, code_sent_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(code, minutesFromNow(CODE_TTL_MINUTES), reg.id);

  await sendEmail({
    to: emailLower,
    subject: `NCMSoft Doğrulama Kodunuz: ${code}`,
    html: verifyCodeEmailHtml(reg.first_name, code, CODE_TTL_MINUTES),
  });
  if (reg.phone) {
    sendSms({ to: reg.phone, message: `NCMSoft demo dogrulama kodunuz: ${code} (${CODE_TTL_MINUTES} dk gecerli)` })
      .catch((e) => console.error('[SMS] resend:', e.message));
  }

  res.json({ ok: true, message: 'Yeni doğrulama kodu gönderildi.' });
});

// ── API: ONBOARD CONTEXT (wizard ön-doldurma) ─────────────────────────────
app.get('/api/onboard-context', (req, res) => {
  const token = String(req.query.token || '').trim();
  if (!token) return res.status(400).json({ ok: false, error: 'Jeton zorunludur.' });

  const reg = db.prepare('SELECT * FROM registrations WHERE onboard_token = ?').get(token);
  if (!reg) return res.status(401).json({ ok: false, error: 'Geçersiz jeton.' });
  if (reg.provisioned) {
    return res.json({
      ok: true,
      alreadyProvisioned: true,
      pendingApproval: true,
      message: 'Demo şirket kurulumu oluşturulmuş ve yönetici onayı bekliyor.',
    });
  }
  if (!reg.verified || isExpired(reg.onboard_expires_at)) {
    return res.status(410).json({ ok: false, error: 'Oturum süresi dolmuş.', expired: true });
  }

  res.json({
    ok: true,
    prefill: {
      first_name: reg.first_name,
      last_name: reg.last_name,
      email: reg.email,
      phone: reg.phone || '',
      company: reg.company || '',
    },
  });
});

// ── API: ONBOARD (tenant + company + user kurulum sihirbazı) ───────────────
app.post('/api/onboard', rateLimit('onboard', {
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyFn: getRealIP,
}), async (req, res) => {
  const { token } = req.body || {};
  const onboardToken = String(token || '').trim();
  if (!onboardToken) return res.status(400).json({ ok: false, error: 'Kurulum jetonu zorunludur.' });

  const reg = db.prepare('SELECT * FROM registrations WHERE onboard_token = ?').get(onboardToken);
  if (!reg) return res.status(401).json({ ok: false, error: 'Geçersiz kurulum jetonu.' });
  if (reg.provisioned) {
    return res.json({
      ok: true,
      alreadyProvisioned: true,
      pendingApproval: true,
      message: 'Demo şirket kurulumu oluşturulmuş ve yönetici onayı bekliyor.',
    });
  }
  if (!reg.verified || isExpired(reg.onboard_expires_at)) {
    return res.status(410).json({ ok: false, error: 'Kurulum oturumunun süresi dolmuş. Lütfen yeniden doğrulayın.', expired: true });
  }

  if (!DEMO_PROVISION_KEY) {
    return res.status(503).json({ ok: false, error: 'Sistem kurulumu şu anda devre dışı (provision anahtarı yok).' });
  }

  // ── Sihirbaz verisini backend provision formatına eşle ────────────────
  const b = req.body || {};
  const adminEmail = String(b.adminEmail || reg.email || '').trim().toLowerCase();
  const payload = {
    mode: 'NEW_TENANT',
    tenantName: b.tenantName,
    tenantCode: b.tenantCode,
    companyTitle: b.companyTitle,
    companyCode: b.companyCode,
    taxNumber: b.taxNumber,
    countryCode: b.countryCode || 'TR',
    currencyCode: b.currencyCode || 'TRY',
    timeZone: b.timeZone || 'Europe/Istanbul',
    adminUser: {
      fullName: b.adminFullName || `${reg.first_name} ${reg.last_name}`.trim(),
      email: adminEmail,
      password: b.adminPassword,
      phone: b.adminPhone || reg.phone || null,
      language: b.adminLanguage || 'tr',
    },
  };

  try {
    const result = await callBackendApi('/api/demo/onboard', 'POST', payload, { 'x-demo-key': DEMO_PROVISION_KEY });

    if (result.status !== 200 && result.status !== 201) {
      const msg = result.body?.error || result.body?.message || 'Kurulum başarısız oldu.';
      return res.status(result.status || 500).json({ ok: false, error: msg });
    }

    // ── Jetonu tüket + kurulum tamamlandı olarak işaretle ───────────────
    db.prepare(`
      UPDATE registrations
      SET provisioned = 1, provisioned_at = CURRENT_TIMESTAMP,
          onboard_token = NULL, admin_email = ?
      WHERE id = ?
    `).run(adminEmail, reg.id);

    // ── Kullanıcıya "onay bekliyor" e-postası ───────────────────────────
    // Kullanıcı PASİF oluşturuldu; girişe ancak SUPERADMIN onayından sonra
    // izin verilir (login pasif kullanıcıyı engeller).
    sendEmail({
      to: reg.email,
      subject: 'NCMSoft — Kaydınız Alındı, Onay Bekleniyor ⏳',
      html: pendingApprovalEmailHtml(reg.first_name, {
        companyTitle: payload.companyTitle,
        adminEmail,
      }),
    }).catch(console.error);

    // Admin bildirimi: yeni kurulum ONAY bekliyor (aksiyon gerekiyor)
    sendEmail({
      to: DEMO_NOTIFY_EMAIL,
      subject: `[NCMSoft] ⏳ ONAY BEKLİYOR — ${payload.companyTitle} (${adminEmail})`,
      html: adminNotifyHtml({
        first_name: reg.first_name, last_name: reg.last_name, email: reg.email,
        phone: reg.phone, company: payload.companyTitle, ip: getRealIP(req),
        note: 'Bu kullanıcı PASİF oluşturuldu. Süper admin panelinden onaylanana kadar giriş yapamaz.',
      }),
    }).catch(console.error);

    res.status(201).json({
      ok: true,
      pendingApproval: true,
      loginUrl: DEMO_URL,
      adminEmail,
      data: result.body?.data || null,
      message: 'Kurulum tamamlandı. Hesabınız yönetici onayına gönderildi.',
    });
  } catch (err) {
    console.error('[Onboard] Backend hatası:', err.message);
    res.status(502).json({ ok: false, error: 'Kurulum servisine ulaşılamadı. Lütfen tekrar deneyin.' });
  }
});

// Eski linkli doğrulama/provision akışı aktif demo kullanıcı oluşturuyordu.
// Yeni modelde tek yol: kod doğrulama -> kurulum formu -> SUPERADMIN onayı.
app.get('/api/verify/:token', (_req, res) => {
  res.redirect('/verify.html?status=legacy_disabled');
});

// ── ADMIN API ─────────────────────────────────────────────
app.get('/api/admin/stats', adminAuth, (req, res) => {
  res.json({
    totalVisitors:   db.prepare('SELECT COUNT(*) c FROM visitors').get().c,
    uniqueIPs:       db.prepare('SELECT COUNT(DISTINCT ip) c FROM visitors').get().c,
    totalRegs:       db.prepare('SELECT COUNT(*) c FROM registrations').get().c,
    verifiedRegs:    db.prepare('SELECT COUNT(*) c FROM registrations WHERE verified=1').get().c,
    provisionedRegs: db.prepare('SELECT COUNT(*) c FROM registrations WHERE provisioned=1').get().c,
    todayVisitors:   db.prepare("SELECT COUNT(*) c FROM visitors WHERE date(created_at)=date('now')").get().c,
    todayRegs:       db.prepare("SELECT COUNT(*) c FROM registrations WHERE date(created_at)=date('now')").get().c,
  });
});

app.get('/api/admin/registrations', adminAuth, (req, res) => {
  res.json(db.prepare(`
    SELECT id, first_name, last_name, email, phone, company,
           verified, verified_at, provisioned, provisioned_at, admin_email,
           ip, user_agent, created_at
    FROM registrations ORDER BY created_at DESC
  `).all());
});

app.get('/api/admin/visitors', adminAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
  res.json(db.prepare('SELECT * FROM visitors ORDER BY created_at DESC LIMIT ?').all(limit));
});

app.get('/api/admin/analytics', adminAuth, (req, res) => {
  res.json({
    browsers:  db.prepare("SELECT browser_name name, COUNT(*) cnt FROM visitors GROUP BY browser_name ORDER BY cnt DESC LIMIT 8").all(),
    os:        db.prepare("SELECT os_name name, COUNT(*) cnt FROM visitors GROUP BY os_name ORDER BY cnt DESC LIMIT 8").all(),
    devices:   db.prepare("SELECT device_type name, COUNT(*) cnt FROM visitors GROUP BY device_type ORDER BY cnt DESC").all(),
    referrers: db.prepare("SELECT referrer name, COUNT(*) cnt FROM visitors WHERE referrer!='' GROUP BY referrer ORDER BY cnt DESC LIMIT 10").all(),
    daily:     db.prepare("SELECT date(created_at) day, COUNT(*) cnt FROM visitors GROUP BY day ORDER BY day DESC LIMIT 30").all(),
    languages: db.prepare("SELECT language name, COUNT(*) cnt FROM visitors WHERE language!='' GROUP BY language ORDER BY cnt DESC LIMIT 10").all(),
  });
});

// Delete registration (admin)
app.delete('/api/admin/registrations/:id', adminAuth, (req, res) => {
  db.prepare('DELETE FROM registrations WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── EMAIL TEMPLATES ───────────────────────────────────────
function verifyCodeEmailHtml(firstName, code, ttlMinutes) {
  return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NCMSoft — Doğrulama Kodu</title></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:Inter,Arial,sans-serif;">
<div style="max-width:560px;margin:40px auto;background:#1e293b;border-radius:16px;overflow:hidden;border:1px solid rgba(255,255,255,0.08);">
  <div style="background:linear-gradient(135deg,#1d4ed8,#7c3aed);padding:36px;text-align:center;">
    <div style="display:inline-flex;align-items:center;gap:10px;margin-bottom:8px;">
      <div style="width:42px;height:42px;background:rgba(255,255,255,0.2);border-radius:10px;display:inline-flex;align-items:center;justify-content:center;font-size:20px;font-weight:900;color:#fff;">N</div>
      <span style="color:#fff;font-size:22px;font-weight:800;">NCMSoft</span>
    </div>
    <p style="color:rgba(255,255,255,0.75);margin:4px 0 0;font-size:13px;letter-spacing:.3px;">Akıllı Lojistik Yönetim Platformu</p>
  </div>
  <div style="padding:40px 36px;">
    <h2 style="color:#f1f5f9;font-size:22px;margin:0 0 14px;font-weight:700;">Merhaba ${firstName}! 👋</h2>
    <p style="color:#94a3b8;font-size:15px;line-height:1.75;margin:0 0 24px;">
      Demo kurulumunu başlatmak için aşağıdaki doğrulama kodunu ekrana girin.
    </p>
    <div style="text-align:center;margin:28px 0;">
      <div style="display:inline-block;background:#0f172a;border:1px solid rgba(37,99,235,0.4);border-radius:14px;padding:22px 36px;">
        <span style="font-family:'Courier New',monospace;font-size:40px;font-weight:800;letter-spacing:14px;color:#93c5fd;">${code}</span>
      </div>
    </div>
    <div style="background:rgba(37,99,235,0.08);border:1px solid rgba(37,99,235,0.2);border-radius:10px;padding:16px 20px;margin-bottom:24px;">
      <p style="color:#93c5fd;font-size:13px;margin:0;line-height:1.6;">
        ⏱️ Bu kod <strong>${ttlMinutes} dakika</strong> geçerlidir.<br>
        🔒 Kodu kimseyle paylaşmayın.
      </p>
    </div>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,0.07);margin:24px 0;">
    <p style="color:#475569;font-size:12px;line-height:1.6;text-align:center;">
      Bu isteği siz yapmadıysanız bu e-postayı görmezden gelebilirsiniz.
    </p>
  </div>
</div>
</body></html>`;
}

function pendingApprovalEmailHtml(firstName, { companyTitle, adminEmail }) {
  return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NCMSoft — Onay Bekleniyor</title></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:Inter,Arial,sans-serif;">
<div style="max-width:560px;margin:40px auto;background:#1e293b;border-radius:16px;overflow:hidden;border:1px solid rgba(255,255,255,0.08);">
  <div style="background:linear-gradient(135deg,#1d4ed8,#7c3aed);padding:40px;text-align:center;">
    <div style="font-size:52px;margin-bottom:12px;">⏳</div>
    <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800;">Kaydınız Alındı!</h1>
  </div>
  <div style="padding:40px 36px;">
    <h2 style="color:#f1f5f9;font-size:22px;margin:0 0 14px;">Teşekkürler ${firstName}! 🎉</h2>
    <p style="color:#94a3b8;font-size:15px;line-height:1.75;margin:0 0 24px;">
      <strong style="color:#f1f5f9;">${companyTitle || 'Şirketiniz'}</strong> için kurulum tamamlandı.
      Hesabınız güvenlik gereği <strong style="color:#f1f5f9;">yönetici onayına</strong> gönderildi.
      Onaylandıktan sonra aşağıdaki bilgilerle giriş yapabileceksiniz:
    </p>
    <div style="background:#0f172a;border:1px solid rgba(37,99,235,0.4);border-radius:12px;padding:20px;margin-bottom:24px;">
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="color:#64748b;font-size:13px;padding:6px 0;width:110px;">Yönetici</td>
            <td style="color:#93c5fd;font-size:14px;font-family:monospace;padding:6px 0;">${adminEmail}</td></tr>
        <tr><td style="color:#64748b;font-size:13px;padding:6px 0;">Şifre</td>
            <td style="color:#a78bfa;font-size:13px;padding:6px 0;">Kurulumda belirlediğiniz şifre</td></tr>
      </table>
    </div>
    <div style="background:rgba(234,179,8,0.08);border:1px solid rgba(234,179,8,0.25);border-radius:10px;padding:14px 18px;margin-bottom:8px;">
      <p style="color:#fbbf24;font-size:13px;margin:0;line-height:1.6;">
        ⏳ Onay tamamlanınca bilgilendirileceksiniz. Onaydan önce yapılan giriş denemeleri
        "Kullanıcı pasif" uyarısı verir — bu normaldir.
      </p>
    </div>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,0.07);margin:24px 0;">
    <p style="color:#475569;font-size:12px;text-align:center;">NCMSoft — Akıllı Lojistik Yönetim Platformu</p>
  </div>
</div>
</body></html>`;
}

function adminNotifyHtml({ first_name, last_name, email, phone, company, ip, note }) {
  const rows = [
    ['Ad Soyad', `${first_name} ${last_name}`],
    ['E-posta', email],
    ['Telefon', phone || '—'],
    ['Firma', company || '—'],
    ['IP Adresi', ip],
    ['Tarih', new Date().toLocaleString('tr-TR')],
  ];
  const noteHtml = note
    ? `<div style="background:rgba(234,179,8,0.1);border:1px solid rgba(234,179,8,0.3);border-radius:10px;padding:14px 18px;margin-top:20px;color:#fbbf24;font-size:13px;line-height:1.6;">⚠️ ${note}</div>`
    : '';
  return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:Arial,sans-serif;">
<div style="max-width:560px;margin:40px auto;background:#1e293b;border-radius:16px;padding:36px;border:1px solid rgba(255,255,255,0.08);">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px;">
    <div style="width:40px;height:40px;background:linear-gradient(135deg,#2563eb,#7c3aed);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:900;color:#fff;">N</div>
    <div>
      <div style="color:#f1f5f9;font-weight:700;font-size:16px;">NCMSoft — Yeni Demo Kaydı</div>
      <div style="color:#94a3b8;font-size:12px;">Admin Bildirimi</div>
    </div>
  </div>
  <table style="width:100%;border-collapse:collapse;">
    ${rows.map(([k, v]) => `
    <tr>
      <td style="color:#64748b;padding:10px 0;font-size:13px;width:110px;border-bottom:1px solid rgba(255,255,255,0.05);">${k}</td>
      <td style="color:#f1f5f9;font-size:14px;font-weight:600;border-bottom:1px solid rgba(255,255,255,0.05);padding:10px 0;">${v}</td>
    </tr>`).join('')}
  </table>
  ${noteHtml}
</div>
</body></html>`;
}

// ── START ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ NCMSoft sunucu çalışıyor → http://localhost:${PORT}`);
  console.log(`🔒 Admin paneli         → http://localhost:${PORT}/admin.html`);
  console.log(`📊 API stats            → http://localhost:${PORT}/api/admin/stats\n`);
});
