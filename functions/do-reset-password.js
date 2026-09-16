import { hashPassword, makeSessionToken, sessionCookieHeader } from './_utils.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const body = await request.json().catch(() => ({}));
    const otp = (body.otp || '').toString().trim();
    const password = (body.password || '').toString();

  const record = await env.PASSWORD_KV.get('otp');
  if (!record) {
    return new Response(JSON.stringify({ error: 'Code expired or not requested' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const { code, exp } = JSON.parse(record);
  if (Math.floor(Date.now() / 1000) > exp || otp !== code) {
    return new Response(JSON.stringify({ error: 'Invalid or expired code' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  if (password.length < 8) {
    return new Response(JSON.stringify({ error: 'Password must be at least 8 characters' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const { hash, salt } = await hashPassword(password);
  await env.PASSWORD_KV.put('password', JSON.stringify({ hash, salt }));
  await env.PASSWORD_KV.delete('otp');
  const token = await makeSessionToken(env.SESSION_SECRET);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookieHeader(token) }
  });
}
