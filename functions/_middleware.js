import { getCookie, verifySessionToken } from './_utils.js';

const PUBLIC_PATHS = new Set(['/login.html', '/setup.html', '/reset.html', '/favicon.ico']);

export async function onRequest(context) {
const { request, next, env } = context;
const url = new URL(request.url);
const path = url.pathname;

// Let API endpoints and public auth pages through untouched.
if (path.startsWith('/do-') || PUBLIC_PATHS.has(path)) {
return next();
}

const pwRecord = await env.PASSWORD_KV.get('password');
if (!pwRecord) {
// No password set yet -- force first-time setup.
if (path !== '/setup.html') return Response.redirect(url.origin + '/setup.html', 302);
return next();
}

const token = getCookie(request, 'session');
const ok = await verifySessionToken(token, env.SESSION_SECRET);
if (!ok) {
if (path !== '/login.html') return Response.redirect(url.origin + '/login.html', 302);
return next();
}

return next();
}
