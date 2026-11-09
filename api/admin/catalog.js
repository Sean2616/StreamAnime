"use strict";
/* GET/PUT /api/admin/catalog — baca & simpan katalog (wajib login admin) */
module.exports = (req, res) => require("../_lib").handleAdminCatalog(req, res);
