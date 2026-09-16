import { verifyPassword, makeSessionToken, sessionCookieHeader } from './_utils.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const record = await env.PASSWORD_KV.get('password');
  if (!record) {
    return new Response(JSON.stringify({ error: 'No password set' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const { hash, salt } = JSON.parse(record);
  const body = await request.json().catch(() => ({}));
    const password = (body.password || '').toString();
    const ok = await verifyPassword(password, salt, hash);
  if (!ok) {
    return new Response(JSON.stringify({ error: 'Incorrect password' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }
  const token = await makeSessionToken(env.SESSION_SECRET);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookieHeader(token) }
  });
}
