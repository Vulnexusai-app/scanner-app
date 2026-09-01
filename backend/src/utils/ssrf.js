/**
 * Utilitários de proteção SSRF — validação de hostname/IP resolvidos.
 * Extraídos para uso tanto no middleware ssrfGuard quanto no engine de scan.
 */
const dns = require("node:dns/promises");

// ─── Notações alternativas de IPv4 ───────────────────────────────────────────
/**
 * Converte cada octeto de um IPv4 para o formato decimal, aceitando notações
 * decimal, octal (066) e hexadecimal (0x1f), além da forma mais longa com
 * números de 8/16/24 bits por posição. Node rejeita essas em `new URL()`,
 * mas cli/axios podem truncá-las e resolver via libc — risco de bypass.
 * Retorna o IPv4 decimal canônico ou null se inválido.
 */
function ipv4Canonico(input) {
  if (typeof input !== "string") return null;
  const s = input.trim();
  if (!s) return null;

  const partes = s.split(".");
  if (partes.length < 1 || partes.length > 4) return null;

  // Converte um segmento (aceitando decimal/octal/hex) para número.
  // Conceitos do mundo real: um octeto com zero à esquerda é OCTAL (ex. 0177 =
  // 127), hex com 0x também. Seguimos o comportamento dos resolvers clássicos.
  const paraNum = (seg) => {
    const m = seg.match(/^(0[xX][0-9a-fA-F]+|0[0-7]+|[0-9]+)$/);
    if (!m) return null;
    const inteiro = m[1].startsWith("0x") || m[1].startsWith("0X")
      ? parseInt(m[1], 16)
      : m[1].startsWith("0") && m[1].length > 1
        ? parseInt(m[1], 8)
        : parseInt(m[1], 10);
    if (!Number.isInteger(inteiro) || inteiro < 0 || inteiro > 255) return null;
    return inteiro;
  };

  try {
    if (partes.length === 4) {
      const nums = partes.map(paraNum);
      if (nums.some(n => n === null)) return null;
      return nums.join(".");
    }

    // Formas curtas: "127.1" => 127.0.0.1; "2130706433" => 127.0.0.1;
    // "0x7f.0x1" etc. Node não resolve estas via IPv4 normal, mas alguns
    // resolvers (ex.: getaddrinfo) interpretam "a.b.c.d" com menos octetos.
    // Para cobertura completa, convertemos por leitura manual.
    let valor = 0;
    const segs = partes.length;
    for (let i = 0; i < segs; i++) {
      const seg = partes[i];
      if (!/^[0-9]+$/.test(seg)) return null;
      const n = Number(seg);
      if (!Number.isInteger(n) || n < 0 || n > 4294967295) return null;
      valor = (valor * 256) + n;
    }
    return [(valor >>> 24) & 0xff, (valor >>> 16) & 0xff, (valor >>> 8) & 0xff, valor & 0xff].join(".");
  } catch {
    return null;
  }
}

/**
 * Decodifica um IPv4 dado como inteiro decimal (ex.: 2130706433 -> 127.0.0.1),
 * octal (012700000001) ou hexadecimal (0x7f000001).
 */
function ipv4DeNotacaoAlternativa(input) {
  if (typeof input !== "string") return null;
  const s = input.trim();
  if (!/^(0x[0-9a-f]+|\d+)$/i.test(s)) return null;
  let n;
  if (/^0x/i.test(s)) {
    n = parseInt(s, 16);
  } else if (/^0[0-7]+$/.test(s)) {
    n = parseInt(s, 8);
  } else {
    n = Number(s);
  }
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) return null;
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join(".");
}

/**
 * Normaliza um endereço IP (IPv4 ou IPv6) para a forma canônica, expandindo
 * notações alternativas. Retorna a string canônica ou null se não reconhecido.
 */
function normalizaIP(ip) {
  if (typeof ip !== "string") return null;
  const s = ip.trim().toLowerCase();
  if (!s) return null;

  // IPv4-mapped IPv6 (ex.: ::ffff:127.0.0.1) -> converte para IPv4.
  const mappedIPv6 = s.match(/^::ffff:(.+)$/);
  if (mappedIPv6) return normalizaIP(mappedIPv6[1]);

  // IPv4 puro ou notação alternativa.
  if (s.includes(".") || /^0x|^0[0-7]+$/.test(s) || /^\d+$/.test(s)) {
    const canonico = ipv4Canonico(s) || ipv4DeNotacaoAlternativa(s);
    if (canonico) return canonico;
    return null;
  }

  // IPv6 — tenta normalizar via parsers do Node.
  try {
    const { isIP } = require("node:net");
    if (isIP(s) === 6) {
      // Getaddrinfo moderno já normaliza; aqui apenas garantimos expansão mínima.
      return s.replace(/(^|:)0+(?=\d)/g, "$1").replace("::ffff:0:0:0:0:0:0:0", "::ffff:0:0");
    }
  } catch {
    /* noop */
  }
  return null;
}

// ─── Faixas perigosas ────────────────────────────────────────────────────────
function bytes4(ipv4) {
  return ipv4.split(".").map(Number);
}

/**
 * Verifica se um endereço IP (IPv4 ou IPv6) cai em faixas privadas, de
 * loopback, link-local, multicast, APIPA/metadata ou não-roteáveis.
 */
function isIPProibido(ip) {
  const norm = normalizaIP(ip);
  if (!norm) return false;

  const { isIP } = require("node:net");
  const fam = isIP(norm);

  if (fam === 4) {
    const [a, b, c] = bytes4(norm);
    if (a === 0) return true;            // 0.0.0.0/8
    if (a === 10) return true;           // 10.0.0.0/8
    if (a === 127) return true;          // loopback
    if (a === 169 && b === 254) return true; // link-local / APIPA
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
    if (a === 192 && b === 168) return true; // 192.168/16
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
    if (a === 192 && b === 0 && c === 2) return true; // 192.0.0.0/24 (documentação/delegados) — 192.0.2.x é EXEMPLO, mas 192.0.0.2 é IETF
    if (a === 198 && b === 18) return true; // 198.18/15 (benchmark)
    if (a === 224 || a >= 240) return true; // multicast 224/4 + reservado 240/4 (incluindo broadcast 255.)
    return false;
  }

  if (fam === 6) {
    const low = norm.toLowerCase();
    if (low === "::" || low === "::1") return true; // unspecified + loopback
    if (low.startsWith("fe80:")) return true;       // link-local fe80::/10
    if (low.startsWith("fc") || low.startsWith("fd")) return true; // unique local fc00::/7
    if (low.startsWith("ff")) return true;          // multicast ff00::/8
    if (low.startsWith("::ffff:")) return true;     // mapped IPv4 (já tratado, mas por segurança)
    if (low.startsWith("::")) return true;          // endereços compressados de baixo (::/96 via IPv4-compat)
    // fec0::/10 (site-local obsoleto)
    if (low.startsWith("fec") || low.startsWith("fed") || low.startsWith("fee") || low.startsWith("fef")) return true;
    return false;
  }

  // Hostname literal que não virou "numérico" — deixamos a checagem de DNS agir.
  return false;
}

// ─── Resolução DNS + validação ───────────────────────────────────────────────
/**
 * Resolve o hostname e verifica se TODOS os IPs resultantes são públicos.
 * Lança um erro (tipo SSRFError) se algum IP for privado/loopback/link-local
 * ou se o hostname não resolver para endereço público.
 */
class SSRFError extends Error {
  constructor(mensagem) {
    super(mensagem);
    this.name = "SSRFError";
  }
}

async function validarHostPublico(hostname) {
  // IP já literal na URL — valida direto (incluindo notações alternativas).
  const ipLiteral = normalizaIP(hostname);
  if (ipLiteral) {
    if (isIPProibido(hostname) || isIPProibido(ipLiteral)) {
      throw new SSRFError("Endereço IP privado/interno bloqueado por segurança (SSRF)");
    }
    return true;
  }

  // Resolve via DNS (IPv4 e IPv6). `all: true` enumera todos os endereços.
  let enderecos = [];
  try {
    const r = await dns.lookup(hostname, { all: true, verbatim: true });
    enderecos = Array.isArray(r) ? r.map(x => x.address) : [];
  } catch (e) {
    throw new SSRFError(`Não foi possível resolver o domínio: ${(e && e.message) || "falha de DNS"}`);
  }

  if (enderecos.length === 0) {
    throw new SSRFError("O domínio não resolveu para nenhum endereço");
  }

  for (const addr of enderecos) {
    const ip = addr.replace(/\[|\]/g, "");
    if (isIPProibido(ip)) {
      throw new SSRFError(
        `O domínio resolve para um endereço interno (${ip}) — bloqueado por segurança (SSRF)`
      );
    }
  }
  return true;
}

module.exports = {
  SSRFError,
  validarHostPublico,
  isIPProibido,
  normalizaIP,
  ipv4Canonico,
  ipv4DeNotacaoAlternativa,
};