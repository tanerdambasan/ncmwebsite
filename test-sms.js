#!/usr/bin/env node
/**
 * SMS gönderim test aracı.
 * ─────────────────────────────────────────────────────────────────────────
 * .env'deki SMS_PROVIDER ve ilgili kimlik bilgilerini kullanarak tek bir
 * test SMS'i gönderir. Sağlayıcıyı canlıya almadan önce doğrulamak içindir.
 *
 * Kullanım:
 *   node test-sms.js 5551112233
 *   node test-sms.js 5551112233 "Ozel mesaj metni"
 *
 * Not: SMS_PROVIDER=log ise gerçek gönderim yapılmaz, sadece konsola yazar.
 * ─────────────────────────────────────────────────────────────────────────
 */
require('dotenv').config();
const { sendSms, normalizeTrMsisdn } = require('./sms');

(async () => {
  const to = process.argv[2];
  const message = process.argv[3] || `NCMSoft test kodu: ${String(Math.floor(Math.random() * 1e6)).padStart(6, '0')}`;

  if (!to) {
    console.error('Kullanım: node test-sms.js <telefon> [mesaj]');
    console.error('Örnek:    node test-sms.js 5551112233');
    process.exit(1);
  }

  const provider = process.env.SMS_PROVIDER || 'log';
  console.log('─'.repeat(60));
  console.log(`Sağlayıcı : ${provider}`);
  console.log(`Numara    : ${to}  (normalize: ${normalizeTrMsisdn(to)})`);
  console.log(`Başlık    : ${process.env.SMS_FROM || 'NCMSOFT'}`);
  console.log(`Mesaj     : ${message}`);
  console.log('─'.repeat(60));

  if (provider === 'log') {
    console.warn('⚠️  SMS_PROVIDER=log — gerçek gönderim yapılmayacak. Canlı test için .env\'de netgsm/twilio/http ayarlayın.');
  }

  const result = await sendSms({ to, message });
  console.log('\nSonuç:', JSON.stringify(result, null, 2));
  process.exit(result.ok ? 0 : 1);
})();
