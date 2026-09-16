import { genOtp, sendOtpEmail } from './_utils.js';

export async function onRequestPost(context) {
  const { env } = context;
  const code = genOtp();
  const record = JSON.stringify({ code, exp: Math.floor(Date.now() / 1000) + 600 });
  await env.PASSWORD_KV.put('otp', record, { expirationTtl: 600 });
  const sent = await sendOtpEmail(env, code);
  if (!sent) {
    return new Response(JSON.stringify({ error: 'Failed to send email' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
}
