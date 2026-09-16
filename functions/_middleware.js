import { getCookie, verifySessionToken } from './_utils.js';
const PUBLIC_PATHS = new Set(['/login', '/setup', '/reset', '/favicon.ico']);
export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  if (path.startsWith('/do-') || PUBLIC_PATHS.has(path)) {
    return next();
  }
  const pwRecord = await env.PASSWORD_KV.get('password');
  if (!pwRecord) {
    if (path !== '/setup') return Response.redirect(url.origin + '/setup', 302);
    return next();
  }
  const token = getCookie(request, 'session');
  const ok = await verifySessionToken(token, env.SESSION_SECRET);
  if (!ok) {
    if (path !== '/login') return Response.redirect(url.origin + '/login', 302);
    return next();
  }
  return next();
}
