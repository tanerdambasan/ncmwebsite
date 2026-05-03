require('dotenv').config();
const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { UAParser } = require('ua-parser-js');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const ADMIN_KEY = process.env.ADMIN_KEY || 'ncmsoft-admin-2025';
const DEMO_URL = process.env.DEMO_URL || 'http://portal.ncmteknoloji.com';
const BACKEND_INTERNAL_URL = process.env.BACKEND_INTERNAL_URL || 'http://localhost:3000';
const DEMO_PROVISION_KEY = process.env.DEMO_PROVISION_KEY || '';

// Ensure data directory exists
if (!fs.existsSync('./data')) fs.mkdirSync('./data');

// ── DATABASE ─────────────────────────────────────────────
const db = new DatabaseSync('./data/ncmsoft.db');

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

// ── MIDDLEWARE ────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname)));

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

function adminAuth(req, res, next) {
  const key = req.query.key || req.headers['x-admin-key'];
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'Yetkisiz erişim.' });
  next();
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
app.post('/api/track', (req, res) => {
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
app.post('/api/register', async (req, res) => {
  const { first_name, last_name, email, phone, company } = req.body || {};

  if (!first_name?.trim() || !last_name?.trim() || !email?.trim()) {
    return res.status(400).json({ ok: false, error: 'Ad, soyad ve e-posta zorunludur.' });
  }

  const emailLower = email.trim().toLowerCase();

  try {
    const existing = db.prepare('SELECT * FROM registrations WHERE email = ?').get(emailLower);

    if (existing) {
      if (existing.verified) {
        return res.json({ ok: true, message: 'Bu e-posta zaten doğrulanmış. Demo portala giriş yapabilirsiniz.' });
      }
      // Resend verification
      const verifyUrl = `${BASE_URL}/api/verify/${existing.verify_token}`;
      await sendEmail({ to: emailLower, subject: 'NCMSoft — Demo Erişim Bağlantısı', html: verifyEmailHtml(existing.first_name, verifyUrl) });
      return res.json({ ok: true, message: 'Doğrulama e-postası tekrar gönderildi. Gelen kutunuzu kontrol edin.' });
    }

    const token = uuidv4();
    const ip = getRealIP(req);
    const ua = req.headers['user-agent'] || '';

    db.prepare(`
      INSERT INTO registrations (first_name, last_name, email, phone, company, verify_token, ip, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(first_name.trim(), last_name.trim(), emailLower, phone?.trim() || '', company?.trim() || '', token, ip, ua);

    const verifyUrl = `${BASE_URL}/api/verify/${token}`;
    await sendEmail({ to: emailLower, subject: 'NCMSoft — Demo Erişim Bağlantısı', html: verifyEmailHtml(first_name.trim(), verifyUrl) });

    if (process.env.ADMIN_EMAIL) {
      sendEmail({
        to: process.env.ADMIN_EMAIL,
        subject: `[NCMSoft] Yeni Demo Kaydı: ${first_name} ${last_name} — ${company || 'Firma belirtilmedi'}`,
        html: adminNotifyHtml({ first_name, last_name, email: emailLower, phone, company, ip }),
      }).catch(console.error);
    }

    res.json({ ok: true, message: 'Kayıt başarılı! Doğrulama bağlantısı e-posta adresinize gönderildi.' });
  } catch (err) {
    console.error('[Register]', err);
    res.status(500).json({ ok: false, error: 'Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.' });
  }
});

// ── API: VERIFY EMAIL ─────────────────────────────────────────────
app.get('/api/verify/:token', async (req, res) => {
  const user = db.prepare('SELECT * FROM registrations WHERE verify_token = ?').get(req.params.token);

  if (!user) return res.redirect('/verify.html?status=invalid');
  if (user.verified) return res.redirect(`${DEMO_URL}`);

  db.prepare('UPDATE registrations SET verified = 1, verified_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

  // ── Demo kullanıcı oluştur (backend üzerinden) ─────────────────────
  let demoEmail = null;
  let demoPassword = null;

  if (DEMO_PROVISION_KEY) {
    try {
      const result = await callBackendApi(
        '/api/demo/provision',
        'POST',
        {
          first_name: user.first_name,
          last_name: user.last_name,
          email: user.email,
          phone: user.phone,
          company: user.company,
        },
        { 'x-demo-key': DEMO_PROVISION_KEY }
      );

      if (result.status === 200 || result.status === 201) {
        demoEmail = result.body.demoEmail;
        demoPassword = result.body.demoPassword;
        console.log(`[Verify] Demo kullanıcı oluşturuldu: ${demoEmail}`);
      } else {
        console.warn('[Verify] Demo kullanıcı oluşturulamadı:', result.body);
      }
    } catch (err) {
      console.error('[Verify] Backend demo provision hatası:', err.message);
    }
  }

  // ── Hoş geldin + credentials e-postası gönder ──────────────────────
  const welcomeHtml = demoEmail && demoPassword
    ? welcomeWithCredentialsEmailHtml(user.first_name, demoEmail, demoPassword)
    : welcomeEmailHtml(user.first_name);

  sendEmail({
    to: user.email,
    subject: 'NCMSoft Demo\'ya Hoş Geldiniz! 🚀',
    html: welcomeHtml,
  }).catch(console.error);

  res.redirect(`/verify.html?status=success&name=${encodeURIComponent(user.first_name)}`);
});

// ── ADMIN API ─────────────────────────────────────────────
app.get('/api/admin/stats', adminAuth, (req, res) => {
  res.json({
    totalVisitors:   db.prepare('SELECT COUNT(*) c FROM visitors').get().c,
    uniqueIPs:       db.prepare('SELECT COUNT(DISTINCT ip) c FROM visitors').get().c,
    totalRegs:       db.prepare('SELECT COUNT(*) c FROM registrations').get().c,
    verifiedRegs:    db.prepare('SELECT COUNT(*) c FROM registrations WHERE verified=1').get().c,
    todayVisitors:   db.prepare("SELECT COUNT(*) c FROM visitors WHERE date(created_at)=date('now')").get().c,
    todayRegs:       db.prepare("SELECT COUNT(*) c FROM registrations WHERE date(created_at)=date('now')").get().c,
  });
});

app.get('/api/admin/registrations', adminAuth, (req, res) => {
  res.json(db.prepare(`
    SELECT id, first_name, last_name, email, phone, company,
           verified, verified_at, ip, user_agent, created_at
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
function verifyEmailHtml(firstName, verifyUrl) {
  return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NCMSoft — E-posta Doğrulama</title></head>
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
    <p style="color:#94a3b8;font-size:15px;line-height:1.75;margin:0 0 28px;">
      NCMSoft demo erişim talebinizi aldık.<br>
      Aşağıdaki butona tıklayarak e-posta adresinizi doğrulayın ve demo portala erişin.
    </p>
    <div style="text-align:center;margin:32px 0;">
      <a href="${verifyUrl}" style="display:inline-block;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;padding:16px 44px;border-radius:10px;font-weight:700;font-size:16px;text-decoration:none;letter-spacing:.3px;">
        ✉️&nbsp;&nbsp;E-postamı Doğrula ve Demo'ya Eriş
      </a>
    </div>
    <div style="background:rgba(37,99,235,0.08);border:1px solid rgba(37,99,235,0.2);border-radius:10px;padding:16px 20px;margin-bottom:24px;">
      <p style="color:#93c5fd;font-size:13px;margin:0;line-height:1.6;">
        ⏱️ Bu bağlantı <strong>48 saat</strong> geçerlidir.<br>
        🔒 Bağlantıya yalnızca siz erişebilirsiniz.
      </p>
    </div>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,0.07);margin:24px 0;">
    <p style="color:#475569;font-size:12px;line-height:1.6;text-align:center;">
      Bu isteği siz yapmadıysanız bu e-postayı görmezden gelebilirsiniz.<br>
      <a href="${verifyUrl}" style="color:#60a5fa;word-break:break-all;">${verifyUrl}</a>
    </p>
  </div>
</div>
</body></html>`;
}

function welcomeEmailHtml(firstName) {
  return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:Inter,Arial,sans-serif;">
<div style="max-width:560px;margin:40px auto;background:#1e293b;border-radius:16px;overflow:hidden;border:1px solid rgba(255,255,255,0.08);">
  <div style="background:linear-gradient(135deg,#1d4ed8,#7c3aed);padding:40px;text-align:center;">
    <div style="font-size:52px;margin-bottom:12px;">🚀</div>
    <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800;">Demo'ya Hoş Geldiniz!</h1>
  </div>
  <div style="padding:40px 36px;">
    <h2 style="color:#f1f5f9;font-size:22px;margin:0 0 14px;">Tebrikler ${firstName}! 🎉</h2>
    <p style="color:#94a3b8;font-size:15px;line-height:1.75;margin:0 0 28px;">
      E-posta adresiniz başarıyla doğrulandı. NCMSoft demo platformuna artık erişebilirsiniz.
    </p>
    <div style="text-align:center;margin:32px 0;">
      <a href="${DEMO_URL}" style="display:inline-block;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;padding:16px 44px;border-radius:10px;font-weight:700;font-size:16px;text-decoration:none;">
        🚀&nbsp;&nbsp;Demo Portala Git
      </a>
    </div>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,0.07);margin:24px 0;">
    <p style="color:#475569;font-size:12px;text-align:center;">NCMSoft — Akıllı Lojistik Yönetim Platformu</p>
  </div>
</div>
</body></html>`;
}

function welcomeWithCredentialsEmailHtml(firstName, demoEmail, demoPassword) {
  return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NCMSoft — Demo Giriş Bilgileri</title></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:Inter,Arial,sans-serif;">
<div style="max-width:560px;margin:40px auto;background:#1e293b;border-radius:16px;overflow:hidden;border:1px solid rgba(255,255,255,0.08);">
  <div style="background:linear-gradient(135deg,#1d4ed8,#7c3aed);padding:40px;text-align:center;">
    <div style="font-size:52px;margin-bottom:12px;">🚀</div>
    <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800;">Demo Hesabınız Hazır!</h1>
  </div>
  <div style="padding:40px 36px;">
    <h2 style="color:#f1f5f9;font-size:22px;margin:0 0 14px;">Tebrikler ${firstName}! 🎉</h2>
    <p style="color:#94a3b8;font-size:15px;line-height:1.75;margin:0 0 24px;">
      E-posta adresiniz doğrulandı. Demo hesabınız oluşturuldu. Aşağıdaki bilgilerle giriş yapabilirsiniz:
    </p>
    <!-- Giriş Bilgileri Kutusu -->
    <div style="background:#0f172a;border:1px solid rgba(37,99,235,0.4);border-radius:12px;padding:24px;margin-bottom:28px;">
      <p style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin:0 0 16px;font-weight:600;">Giriş Bilgileri</p>
      <table style="width:100%;border-collapse:collapse;">
        <tr>
          <td style="color:#64748b;font-size:13px;padding:8px 0;width:90px;border-bottom:1px solid rgba(255,255,255,0.05);">E-posta</td>
          <td style="color:#93c5fd;font-size:14px;font-weight:700;font-family:monospace;border-bottom:1px solid rgba(255,255,255,0.05);padding:8px 0;">${demoEmail}</td>
        </tr>
        <tr>
          <td style="color:#64748b;font-size:13px;padding:8px 0;width:90px;">Şifre</td>
          <td style="color:#a78bfa;font-size:14px;font-weight:700;font-family:monospace;padding:8px 0;">${demoPassword}</td>
        </tr>
      </table>
    </div>
    <div style="background:rgba(234,179,8,0.08);border:1px solid rgba(234,179,8,0.25);border-radius:10px;padding:14px 18px;margin-bottom:28px;">
      <p style="color:#fbbf24;font-size:13px;margin:0;line-height:1.6;">
        🔐 Giriş yaptıktan sonra şifrenizi değiştirmenizi öneririz.<br>
        📱 Demo portal erişimi: <strong>${DEMO_URL}</strong>
      </p>
    </div>
    <div style="text-align:center;margin:28px 0;">
      <a href="${DEMO_URL}" style="display:inline-block;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;padding:16px 44px;border-radius:10px;font-weight:700;font-size:16px;text-decoration:none;">
        🚀&nbsp;&nbsp;Demo Portala Giriş Yap
      </a>
    </div>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,0.07);margin:24px 0;">
    <p style="color:#475569;font-size:12px;text-align:center;">NCMSoft — Akıllı Lojistik Yönetim Platformu</p>
  </div>
</div>
</body></html>`;
}

function adminNotifyHtml({ first_name, last_name, email, phone, company, ip }) {
  const rows = [
    ['Ad Soyad', `${first_name} ${last_name}`],
    ['E-posta', email],
    ['Telefon', phone || '—'],
    ['Firma', company || '—'],
    ['IP Adresi', ip],
    ['Tarih', new Date().toLocaleString('tr-TR')],
  ];
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
</div>
</body></html>`;
}

// ── START ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ NCMSoft sunucu çalışıyor → http://localhost:${PORT}`);
  console.log(`🔒 Admin paneli         → http://localhost:${PORT}/admin.html?key=${ADMIN_KEY}`);
  console.log(`📊 API stats            → http://localhost:${PORT}/api/admin/stats?key=${ADMIN_KEY}\n`);
});
