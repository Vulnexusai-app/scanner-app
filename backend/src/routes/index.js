const express = require("express");
const scanRoutes = require("./scanRoutes");
const userRoutes = require("./userRoutes");
const authRoutes = require("./authRoutes");
const authNew = require("./auth");
const mfaRoutes = require("./mfa");
const exportsRoutes = require("./exports");
const adminRoutes = require("./admin");
const billingRoutes = require("./billing");

const router = express.Router();

router.use("/auth", authRoutes);
router.use("/auth", authNew);
router.use("/auth/mfa", mfaRoutes);
router.use("/scan", scanRoutes);
router.use("/user", userRoutes);
router.use("/billing", billingRoutes);

// Phase 2: Exports and Admin
router.use("/", exportsRoutes);
router.use("/admin", adminRoutes);

// Alias para manter compatibilidade
router.use("/scans", scanRoutes);

module.exports = router;
