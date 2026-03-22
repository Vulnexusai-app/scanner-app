const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, 'frontend');

const htmlFiles = fs.readdirSync(dir).filter(f => f.endsWith('.html'));

const injection = `
<!-- GLOBAL FOOTER & COOKIE BANNER -->
<footer style="margin-top:64px; padding:32px 24px; border-top:1px solid #222; text-align:center; font-size:12px; color:#666;">
  <div style="display:flex; justify-content:center; gap:24px; flex-wrap:wrap; margin-bottom:12px;">
    <a href="/pricing.html" style="color:#888; text-decoration:none;">Preços</a>
    <a href="/terms.html" style="color:#888; text-decoration:none;">Termos de Uso</a>
    <a href="/privacy.html" style="color:#888; text-decoration:none;">Privacidade</a>
    <a href="/cookies.html" style="color:#888; text-decoration:none;">Cookies</a>
    <a href="mailto:suporte@vulnexusai.com" style="color:#888; text-decoration:none;">Suporte</a>
  </div>
  <p style="margin:0;">© 2025 VulnexusAI. Todos os direitos reservados.</p>
  <p style="margin:4px 0 0; font-size:11px;">Use apenas em APIs que você tem autorização para testar.</p>
</footer>
<script>
if(!localStorage.getItem('cookieConsent')){
  const banner=document.createElement('div');
  banner.id='cookieConsent';
  banner.style.cssText='position:fixed;bottom:0;left:0;right:0;background:#111;color:#fff;padding:16px;text-align:center;z-index:9999;border-top:1px solid #333;display:flex;justify-content:center;align-items:center;gap:16px;flex-wrap:wrap;font-size:14px;';
  banner.innerHTML='Utilizamos cookies para melhorar sua experiência. Ao continuar, você aceita nossa <a href="/privacy.html" style="color:#7c3aed;text-decoration:underline;">Política de Privacidade</a>. <button onclick="localStorage.setItem(\\'cookieConsent\\',\\'true\\');document.getElementById(\\'cookieConsent\\').remove()" style="background:#7c3aed;color:#fff;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-weight:bold;">Aceitar</button>';
  document.body.appendChild(banner);
}
</script>
`;

htmlFiles.forEach(f => {
  const filePath = path.join(dir, f);
  let content = fs.readFileSync(filePath, 'utf-8');
  if (!content.includes('GLOBAL FOOTER & COOKIE BANNER') && content.includes('</body>')) {
    content = content.replace('</body>', injection + '\n</body>');
    fs.writeFileSync(filePath, content);
    console.log('Injected into', f);
  }
});
