const crypto = require("node:crypto");

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "799364070845-pqnidruj6bc9o9tm778m8oj9mokpeaq8.apps.googleusercontent.com";
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || "https://fichas-rol.netlify.app/.netlify/functions/oauth-callback";
const COOKIE = "mistborn_drive_session";

function cookieValue(event, name) {
  const raw = event.headers.cookie || event.headers.Cookie || "";
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return "";
}
function sessionCookie(value, maxAge = 2592000) {
  return COOKIE + "=" + encodeURIComponent(value) + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + maxAge;
}
function clearSessionCookie() {
  return COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}
function key() {
  if (!CLIENT_SECRET) throw new Error("Falta GOOGLE_CLIENT_SECRET en las variables de entorno de Netlify.");
  return crypto.createHash("sha256").update(CLIENT_SECRET + "|Fichas-rol OAuth session v1").digest();
}
function seal(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key(), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url");
}
function unseal(value) {
  if (!value) return null;
  try {
    const data = Buffer.from(value, "base64url");
    if (data.length < 29) return null;
    const decipher = crypto.createDecipheriv("aes-256-gcm", key(), data.subarray(0, 12));
    decipher.setAuthTag(data.subarray(12, 28));
    const plain = Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString("utf8");
    return JSON.parse(plain);
  } catch (_) { return null; }
}
function redirect(location, cookies = []) {
  return { statusCode: 302, headers: { Location: location, "Cache-Control": "no-store", ...(cookies.length ? { "Set-Cookie": cookies } : {}) }, body: "" };
}
function json(statusCode, data, cookies = []) {
  return { statusCode, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...(cookies.length ? { "Set-Cookie": cookies } : {}) }, body: JSON.stringify(data) };
}
module.exports = { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, COOKIE, cookieValue, sessionCookie, clearSessionCookie, seal, unseal, redirect, json };
