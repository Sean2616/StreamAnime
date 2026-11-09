"use strict";
/* POST /api/login — login admin (password dicek di server, sesi cookie HMAC) */
module.exports = (req, res) => require("./_lib").handleLogin(req, res);
