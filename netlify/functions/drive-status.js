const { cookieValue, unseal, json } = require("./_oauth");
exports.handler = async (event) => {
  const session = unseal(cookieValue(event, "mistborn_drive_session"));
  return json(200, { connected: !!(session && session.refresh_token) });
};
