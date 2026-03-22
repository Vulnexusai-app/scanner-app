const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, 'frontend');

const htmlFiles = fs.readdirSync(dir).filter(f => f.endsWith('.html'));

const metaTags = `
<!-- SEO META TAGS -->
<meta name="description" content="VulnexusAI — Scanner de segurança para APIs REST e GraphQL. Detecte vulnerabilidades críticas em segundos com Inteligência Artificial.">
<meta name="robots" content="index, follow">
<link rel="canonical" href="https://vulnexusai.com/">
<meta property="og:title" content="VulnexusAI — Segurança de API em segundos">
<meta property="og:description" content="Detecte vulnerabilidades críticas em APIs com IA. Grátis para começar.">
<meta property="og:image" content="https://vulnexusai.com/assets/og-image.png">
<meta property="og:url" content="https://vulnexusai.com">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="https://vulnexusai.com/assets/og-image.png">
`;

htmlFiles.forEach(f => {
  const filePath = path.join(dir, f);
  let content = fs.readFileSync(filePath, 'utf-8');
  if (!content.includes('SEO META TAGS') && content.includes('</head>')) {
    content = content.replace('</head>', metaTags + '\n</head>');
    fs.writeFileSync(filePath, content);
    console.log('Injected SEO into', f);
  }
});
