const crypto = require("node:crypto");
const { CLIENT_ID, REDIRECT_URI, sessionCookie, redirect } = require("./_oauth");

exports.handler = async () => {
  const state = crypto.randomBytes(24).toString("base64url");
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "https://www.googleapis.com/auth/drive.file");
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("include_granted_scopes", "true");
  url.searchParams.set("state", state);
  return redirect(url.toString(), ["mistborn_oauth_state=" + state + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600"]);
};
