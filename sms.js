// ── SMS ALTYAPISI ─────────────────────────────────────────────────────────
// Sağlayıcıdan bağımsız bir SMS gönderim katmanı. env ile yapılandırılır;
// yapılandırma yoksa no-op olarak loglar (geliştirmede kod SMS'i simüle edilir).
// Desteklenen sağlayıcılar: 'netgsm' (önerilen, TR OTP), 'twilio', 'http', 'log'.

// Türk cep numarasını Netgsm formatına indirger: 10 hane, 5 ile başlayan.
// "+90 555 111 22 33", "0555...", "90555..." → "5551112233".
function normalizeTrMsisdn(phone) {
  let d = String(phone || '').replace(/\D/g, '');
  if (d.startsWith('90')) d = d.slice(2);
  else if (d.startsWith('0')) d = d.slice(1);
  return d;
}

// Netgsm GET API yanıt kodlarının Türkçe açıklaması.
function netgsmError(code) {
  const map = {
    '20': 'Mesaj metni/karakter sayısı hatası.',
    '30': 'Geçersiz kullanıcı adı/şifre veya API erişimi/IP izni yok.',
    '40': 'Gönderici başlığı (msgheader) sistemde tanımlı değil.',
    '50': 'İYS aboneliği ile ilgili gönderim engellendi.',
    '51': 'İYS başlığı bulunamadı.',
    '70': 'Hatalı sorgu — parametrelerden biri eksik/yanlış.',
    '80': 'Gönderim sınır aşımı.',
    '85': 'Mükerrer gönderim sınırı (aynı numaraya çok kısa aralıkla).',
  };
  return map[code] || `Bilinmeyen hata (kod: ${code}).`;
}

async function sendSms({ to, message }) {
  const provider = (process.env.SMS_PROVIDER || 'log').toLowerCase();
  const phone = String(to || '').replace(/[^\d+]/g, '');

  if (!phone) {
    console.warn('[SMS] Telefon numarası yok — gönderim atlandı.');
    return { ok: false, skipped: true, reason: 'no_phone' };
  }

  try {
    switch (provider) {
      case 'netgsm': {
        // Netgsm HTTP GET API. Gerçek gönderim için SMS_USER/SMS_PASS/SMS_FROM gerekir.
        // OTP/doğrulama kodu içeriği İYS'den muaftır; yalnızca onaylı gönderici
        // başlığı (msgheader) tanımlı olmalıdır.
        if (!process.env.SMS_USER || !process.env.SMS_PASS) break;
        const gsmno = normalizeTrMsisdn(phone);
        const params = new URLSearchParams({
          usercode: process.env.SMS_USER,
          password: process.env.SMS_PASS,
          gsmno,
          message,
          msgheader: process.env.SMS_FROM || 'NCMSOFT',
          dil: 'TR',
        });
        const url = (process.env.SMS_API_URL || 'https://api.netgsm.com.tr/sms/send/get') + '?' + params.toString();
        const resp = await fetch(url);
        const text = (await resp.text()).trim();
        const code = text.split(/\s+/)[0];               // "00 123456" → "00"
        const ok = resp.ok && code === '00';
        if (ok) {
          console.log(`[SMS][netgsm] ${gsmno} → gönderildi (jobid: ${text.split(/\s+/)[1] || '-'})`);
        } else {
          console.warn(`[SMS][netgsm] ${gsmno} → HATA kodu=${code}: ${netgsmError(code)} (ham: ${text.slice(0, 80)})`);
        }
        return { ok, provider, code, error: ok ? null : netgsmError(code), response: text.slice(0, 200) };
      }
      case 'twilio': {
        if (!process.env.SMS_ACCOUNT_SID || !process.env.SMS_AUTH_TOKEN || !process.env.SMS_FROM) break;
        const sid = process.env.SMS_ACCOUNT_SID;
        const auth = Buffer.from(`${sid}:${process.env.SMS_AUTH_TOKEN}`).toString('base64');
        const body = new URLSearchParams({ To: phone, From: process.env.SMS_FROM, Body: message });
        const resp = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
          method: 'POST',
          headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });
        console.log(`[SMS][twilio] ${phone} → HTTP ${resp.status}`);
        return { ok: resp.ok, provider };
      }
      case 'http': {
        // Generic webhook: SMS_API_URL'e {to, from, message} JSON POST eder.
        if (!process.env.SMS_API_URL) break;
        const resp = await fetch(process.env.SMS_API_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(process.env.SMS_API_KEY ? { Authorization: `Bearer ${process.env.SMS_API_KEY}` } : {}),
          },
          body: JSON.stringify({ to: phone, from: process.env.SMS_FROM || 'NCMSOFT', message }),
        });
        console.log(`[SMS][http] ${phone} → HTTP ${resp.status}`);
        return { ok: resp.ok, provider };
      }
      default:
        break;
    }
  } catch (err) {
    console.error('[SMS] Gönderim hatası:', err.message);
    return { ok: false, provider, error: err.message };
  }

  // Yapılandırma yok / 'log' modu → konsola yaz (geliştirme kolaylığı için).
  console.log(`[SMS][log] ${phone} → "${message}"`);
  return { ok: true, provider: 'log', simulated: true };
}

module.exports = { sendSms, normalizeTrMsisdn, netgsmError };
