const { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, cookieValue, sessionCookie, clearSessionCookie, seal, redirect } = require("./_oauth");

exports.handler = async (event) => {
  const params = event.queryStringParameters || {};
  const expected = cookieValue(event, "mistborn_oauth_state");
  const stateCookie = "mistborn_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
  if (!expected || !params.state || params.state !== expected) {
    return redirect("/?drive_error=state", [stateCookie]);
  }
  if (params.error || !params.code) return redirect("/?drive_error=denied", [stateCookie]);
  if (!CLIENT_SECRET) return redirect("/?drive_error=server_config", [stateCookie]);
  try {
    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: params.code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI, grant_type: "authorization_code"
      })
    });
    const token = await response.json();
    if (!response.ok || !token.refresh_token) {
      console.error("Google token exchange failed:", token.error || response.status, token.error_description || "");
      return redirect("/?drive_error=token", [stateCookie]);
    }
    const session = seal({ refresh_token: token.refresh_token, created_at: Date.now() });
    return redirect("/", [stateCookie, sessionCookie(session)]);
  } catch (error) {
    console.error("OAuth callback failed:", error.message);
    return redirect("/?drive_error=callback", [stateCookie]);
  }
};
