"use strict";
/* GET /api/health */
module.exports = (req, res) => require("./_lib").handleHealth(req, res);
