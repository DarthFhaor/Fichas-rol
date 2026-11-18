const { clearSessionCookie, json } = require("./_oauth");
exports.handler = async () => json(200, { ok: true }, [clearSessionCookie()]);
