const express = require("express");
const scanRoutes = require("./scanRoutes");
const userRoutes = require("./userRoutes");

const router = express.Router();

router.use("/scan", scanRoutes);
router.use("/user", userRoutes);

// Historio em /scans (alias para manter compatibilidade frontend se necessario)
router.use("/scans", scanRoutes);

module.exports = router;
