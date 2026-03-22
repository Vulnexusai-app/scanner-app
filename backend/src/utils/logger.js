function log(nivel, acao, email = "-", detalhe = "") {
  const ts = new Date().toISOString();
  const fn = nivel === "error" ? console.error : console.log;
  fn(`[${ts}] [${nivel.toUpperCase()}] ${acao} | user=${email}${detalhe ? " | " + detalhe : ""}`);
}

module.exports = { log };
