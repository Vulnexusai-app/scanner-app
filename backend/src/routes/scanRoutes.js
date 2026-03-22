const express = require("express");
const { startScan, getHistory } = require("../controllers/scanController");
const { autenticar } = require("../middlewares/auth");
const rateLimit = require("express-rate-limit");

const router = express.Router();

const limitadorScan = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { erro: "Limite de taxa excedido. Tente em 1 minuto." },
});

router.post("/", limitadorScan, autenticar, startScan);
router.get("/", autenticar, getHistory);

module.exports = router;
