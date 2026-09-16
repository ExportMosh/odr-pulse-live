import { hashPassword, makeSessionToken, sessionCookieHeader } from './_utils.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const existing = await env.PASSWORD_KV.get('password');
  if (existing) {
    return new Response(JSON.stringify({ error: 'Password already set' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const body = await request.json().catch(() => ({}));
    const password = (body.password || '').toString();
    if (password.length < 8) {
    return new Response(JSON.stringify({ error: 'Password must be at least 8 characters' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const { hash, salt } = await hashPassword(password);
  await env.PASSWORD_KV.put('password', JSON.stringify({ hash, salt }));
  const token = await makeSessionToken(env.SESSION_SECRET);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookieHeader(token) }
  });
}
