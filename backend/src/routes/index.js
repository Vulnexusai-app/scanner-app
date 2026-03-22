const express = require("express");
const scanRoutes = require("./scanRoutes");
const userRoutes = require("./userRoutes");
const authRoutes = require("./authRoutes");

const router = express.Router();

router.use("/auth", authRoutes);
router.use("/scan", scanRoutes);
router.use("/user", userRoutes);

// Alias para manter compatibilidade
router.use("/scans", scanRoutes);

module.exports = router;
