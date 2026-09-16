// Shared helpers for auth: password hashing, session signing, OTP, email.
// Files starting with "_" are not treated as routes by Cloudflare Pages Functions.

export function toHex(buf) {
return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
export function fromHex(hex) {
const arr = new Uint8Array(hex.length / 2);
for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
return arr;
}

export async function hashPassword(password, saltHex) {
const enc = new TextEncoder();
const salt = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
return { hash: toHex(bits), salt: toHex(salt) };
}

export async function verifyPassword(password, saltHex, hashHex) {
const { hash } = await hashPassword(password, saltHex);
return hash === hashHex;
}

export async function hmac(data, secret) {
const enc = new TextEncoder();
const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
return toHex(sig);
}

export async function makeSessionToken(secret, ttlSeconds = 60 * 60 * 24 * 14) {
const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
const sig = await hmac(String(exp), secret);
return `${exp}.${sig}`;
}

export async function verifySessionToken(token, secret) {
if (!token) return false;
const parts = token.split('.');
if (parts.length !== 2) return false;
const [expStr, sig] = parts;
const exp = parseInt(expStr, 10);
if (!exp || Math.floor(Date.now() / 1000) > exp) return false;
const expected = await hmac(expStr, secret);
return expected === sig;
}

export function getCookie(request, name) {
const cookie = request.headers.get('Cookie') || '';
const match = cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
return match ? decodeURIComponent(match[1]) : null;
}

export function sessionCookieHeader(token, ttlSeconds = 60 * 60 * 24 * 14) {
return `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ttlSeconds}`;
}

export function clearCookieHeader() {
return `session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function genOtp() {
const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
return String(n).padStart(6, '0');
}

export async function sendOtpEmail(env, code) {
const resp = await fetch('https://api.resend.com/emails', {
method: 'POST',
headers: {
Authorization: `Bearer ${env.RESEND_API_KEY}`,
'Content-Type': 'application/json'
},
body: JSON.stringify({
from: 'ODR Pulse <onboarding@resend.dev>',
to: [env.ADMIN_EMAIL],
subject: 'Your ODR Pulse password reset code',
html: `<p>Your one-time verification code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p><p>This code expires in 10 minutes. If you didn't request this, you can ignore this email.</p>`
})
});
return resp.ok;
}
