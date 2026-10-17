// Rebuild the vector identity with the bundled, unmodified Inter 4.1 fonts.
// Usage: node assets/branding/generate.cjs --modules target/branding/node_modules
// Add --png-dir target/branding to export GitHub's upload formats.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const args = process.argv.slice(2);
function option(name) {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}
const modules = option('--modules');
const canvasModule = modules ? path.join(path.resolve(modules), '@napi-rs/canvas') : '@napi-rs/canvas';
const { GlobalFonts, createCanvas, convertSVGTextToPath, loadImage } = require(canvasModule);
const version = require(path.join(modules ? path.resolve(modules) : path.dirname(require.resolve('@napi-rs/canvas/package.json')), modules ? '@napi-rs/canvas/package.json' : 'package.json')).version;
if (version !== '0.1.100') throw new Error('Use @napi-rs/canvas 0.1.100 for the recorded renderer');
const directory = __dirname;
const fonts = [
  ['Inter-Bold.ttf', 'VanityInterBold', '288316099b1e0a47a4716d159098005eef7c0066921f34e3200393dbdb01947f'],
  ['Inter-Medium.ttf', 'VanityInterMedium', '97ad806f526e41546d46365bb3a393145f75b7b1568913db74549ad8b8dba872'],
];
for (const [file, alias, expected] of fonts) {
  const location = path.join(directory, 'fonts', file);
  const actual = crypto.createHash('sha256').update(fs.readFileSync(location)).digest('hex');
  if (actual !== expected) throw new Error(`Font differs from the official Inter 4.1 release: ${file}`);
  if (!GlobalFonts.registerFromPath(location, alias) || !GlobalFonts.has(alias)) throw new Error(`Cannot load ${file}`);
}
const background = '#171b20';
const definition = `<defs>
  <linearGradient id="mint-face" x1="350" y1="210" x2="550" y2="760" gradientUnits="userSpaceOnUse">
    <stop stop-color="#7debe1"/><stop offset="1" stop-color="#37c9c6"/>
  </linearGradient>
  <linearGradient id="teal-face" x1="200" y1="250" x2="610" y2="800" gradientUnits="userSpaceOnUse">
    <stop stop-color="#12aeb1"/><stop offset="1" stop-color="#07888e"/>
  </linearGradient>
</defs>`;
const mark = `<g id="vanity-mark">
  <path fill="url(#teal-face)" d="M150 210H345L512 565 679 210H874L607 755 512 850 417 755Z"/>
  <path fill="url(#mint-face)" d="M150 210H345L512 565 455 686 287 330Z"/>
  <path fill="#0c989e" d="M150 210 287 330 455 686 417 755Z"/>
  <path fill="url(#mint-face)" d="M679 210H874L558 673 417 755 512 565Z"/>
  <path fill="#078c93" d="M874 210 733 330 607 755 558 673Z"/>
  <path fill="#0ca9ae" d="M417 755 558 673 607 755 512 850Z"/>
</g>`;
function svg(width, height, title, content) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="brand-title">
<title id="brand-title">${title}</title>
<metadata>VanityProject. Faceted V in application teal and charcoal. Wordmark: Inter 4.1 Bold 700; attribution: Inter 4.1 Medium 500. Font source: https://github.com/rsms/inter/releases/tag/v4.1. Outlined text; no runtime font dependency.</metadata>
${definition}
<rect width="${width}" height="${height}" fill="${background}"/>
${content}
</svg>\n`;
}
async function main() {
  const avatar = svg(1024, 1024, 'VanityProject organization logo', mark);
  const measure = createCanvas(1, 1).getContext('2d');
  measure.font = '700 140px VanityInterBold';
  const wordWidth = measure.measureText('Vanity Pro').width;
  const scale = 0.46;
  const markWidth = 724 * scale;
  const left = (1280 - markWidth - 48 - wordWidth) / 2;
  const textX = left + markWidth + 48;
  const markX = left - 150 * scale;
  const markY = (640 - 640 * scale) / 2 - 210 * scale;
  const textSource = `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640">
<text x="${textX}" y="330" font-family="VanityInterBold" font-weight="700" font-size="140" fill="#edf2f7">Vanity Pro</text>
<text x="${textX + 4}" y="410" font-family="VanityInterMedium" font-weight="500" font-size="40" fill="#aebac5">by VanityProject</text>
</svg>`;
  const converted = convertSVGTextToPath(textSource).toString('utf8');
  if (/<text\b|<image\b/i.test(converted) || !/<path\b/.test(converted)) throw new Error('Wordmark is not vector outlines');
  const textPaths = converted.match(/<svg\b[^>]*>([\s\S]*)<\/svg>/)[1];
  const banner = svg(1280, 640, 'Vanity Pro by VanityProject', `<g transform="translate(${markX} ${markY}) scale(${scale})">${mark}</g>\n<g id="inter-wordmark">${textPaths}</g>`);
  const outputs = [['vanity-project', avatar], ['vanity-pro', banner]];
  for (const [name, source] of outputs) fs.writeFileSync(path.join(directory, `${name}.svg`), source);
  const pngDirectory = option('--png-dir');
  if (pngDirectory) {
    fs.mkdirSync(pngDirectory, { recursive: true });
    for (const [name, source] of outputs) {
      const image = await loadImage(Buffer.from(source));
      const size = name === 'vanity-project' ? [512, 512] : [1280, 640];
      const raster = createCanvas(...size);
      raster.getContext('2d').drawImage(image, 0, 0, ...size);
      fs.writeFileSync(path.join(pngDirectory, `${name}.png`), raster.toBuffer('image/png'));
    }
  }
  console.log(JSON.stringify(outputs.map(([name, source]) => ({ file: `${name}.svg`, sha256: crypto.createHash('sha256').update(source).digest('hex') }))));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
