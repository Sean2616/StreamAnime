"use strict";
/* POST /api/logout — hapus cookie sesi admin */
module.exports = (req, res) => require("./_lib").handleLogout(req, res);
