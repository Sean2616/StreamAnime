"use strict";
/* GET /api/catalog — katalog publik (seed otomatis bila Firebase masih kosong) */
module.exports = (req, res) => require("./_lib").handlePublicCatalog(req, res);
