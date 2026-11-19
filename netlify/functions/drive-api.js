const { CLIENT_ID, CLIENT_SECRET, cookieValue, unseal, json, sessionCookie } = require("./_oauth");

exports.handler = async (event) => {
  const session = unseal(cookieValue(event, "mistborn_drive_session"));
  if (!session || !session.refresh_token) return json(401, { error: { message: "No hay una sesión de Google Drive. Vuelve a conectar la cuenta." } });
  if (!CLIENT_SECRET) return json(500, { error: { message: "Falta GOOGLE_CLIENT_SECRET en Netlify." } });
  const path = (event.queryStringParameters || {}).path || "";
  if (!path.startsWith("/drive/v3/files") && !path.startsWith("/upload/drive/v3/files")) {
    return json(400, { error: { message: "Ruta de Google Drive no permitida." } });
  }
  let stage = "renovación del token de Google";
  try {
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
        refresh_token: session.refresh_token, grant_type: "refresh_token"
      })
    });
    const token = await tokenResponse.json();
    if (!tokenResponse.ok || !token.access_token) {
      console.error("Google refresh failed:", token.error || tokenResponse.status);
      return json(401, { error: { message: "La autorización de Google ha caducado o ha sido revocada. Desconecta y vuelve a conectar Drive." } });
    }
    stage = "consulta a la API de Google Drive";
    const method = event.httpMethod || "GET";
    const headers = {};
    for (const [name, value] of Object.entries(event.headers || {})) {
      if (["content-type", "content-length", "range"].includes(name.toLowerCase())) headers[name] = value;
    }
    headers.Authorization = "Bearer " + token.access_token;
    const body = event.body ? (event.isBase64Encoded ? Buffer.from(event.body, "base64") : event.body) : undefined;
    const upstream = await fetch("https://www.googleapis.com" + path, { method, headers, ...(body !== undefined ? { body } : {}) });
    if ((event.queryStringParameters || {}).diagnostic === "1" && path.includes("alt=media")) {
      const raw = await upstream.text();
      let summary = { upstreamStatus: upstream.status, contentType: upstream.headers.get("content-type") || "" };
      if (upstream.ok) {
        try {
          const snapshot = JSON.parse(raw);
          summary = { ...summary, validJson: true, topLevelKeys: Object.keys(snapshot || {}).slice(0, 20),
            format: snapshot && snapshot.format || null, version: snapshot && snapshot.version || null,
            profilesCount: Array.isArray(snapshot && snapshot.profiles) ? snapshot.profiles.length : null,
            firstProfileHasSheet: !!(snapshot && snapshot.profiles && snapshot.profiles[0] && snapshot.profiles[0].sheet) };
        } catch (_) { summary.validJson = false; }
      } else {
        summary.googleError = raw.slice(0, 1000);
      }
      return json(upstream.status, summary);
    }
    const bytes = Buffer.from(await upstream.arrayBuffer());
    const responseHeaders = {
      "Content-Type": upstream.headers.get("content-type") || "application/octet-stream",
      "Cache-Control": "no-store"
    };
    const output = {
      statusCode: upstream.status, headers: responseHeaders,
      body: bytes.toString("base64"), isBase64Encoded: true
    };
    if (token.refresh_token && token.refresh_token !== session.refresh_token) {
      output.headers["Set-Cookie"] = sessionCookie(require("./_oauth").seal({ ...session, refresh_token: token.refresh_token }));
    }
    return output;
  } catch (error) {
    console.error("Drive proxy failed at " + stage + ":", error && error.stack ? error.stack : error);
    return json(502, { error: { message: "Fallo durante " + stage + ": " + (error && error.message ? error.message : String(error)) } });
  }
};
