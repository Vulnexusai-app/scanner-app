const express = require("express");
const { getMe, getUsage } = require("../controllers/userController");
const { autenticar } = require("../middlewares/auth");

const router = express.Router();

router.get("/me", autenticar, getMe);
router.get("/usage", autenticar, getUsage);

module.exports = router;
