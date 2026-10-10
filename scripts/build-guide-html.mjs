// Generate the browser-readable offline manual from SETUP.md.
// Optional argument: path to the installed marked ESM module.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const { marked } = await import(process.argv[2] ? pathToFileURL(path.resolve(process.argv[2])).href : 'marked');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const markdown = await fs.readFile(path.join(root,'SETUP.md'),'utf8');
const content = marked.parse(markdown).replace(/<h([1-3])>(.*?)<\/h\1>/g, (_,level,label) => {
  const id=label.replace(/<[^>]+>/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
  return `<h${level} id="${id}">${label}</h${level}>`;
});
const html=`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Elka Network Diagnostics — setup and testing guide</title>
<style>
:root{color-scheme:dark;--bg:#101615;--panel:#192321;--text:#e9f1ed;--muted:#b5c6be;--accent:#75dcc0;--line:#34443f}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:20px}body{margin:0;background:var(--bg);color:var(--text);font:17px/1.65 'Segoe UI',Arial,sans-serif}
header,main,footer{max-width:1100px;margin:auto;padding:24px 32px}header{border-bottom:1px solid var(--line);color:var(--accent);font-weight:650;letter-spacing:.04em}main{padding-top:12px;padding-bottom:48px}
h1,h2,h3{line-height:1.25}h1{font-size:36px;max-width:900px;margin:24px 0}h2{font-size:28px;margin:54px 0 18px;padding-top:20px;border-top:1px solid var(--line)}h3{font-size:22px;margin-top:32px}p,li{max-width:1000px}li{padding:5px 0}li::marker{color:var(--accent);font-weight:650}
a{color:var(--accent);text-underline-offset:4px}a:hover{color:white}a:focus-visible{outline:2px solid var(--accent);outline-offset:4px}strong{color:#fff}
blockquote{margin:24px 0;padding:12px 24px;border-left:4px solid #f3c878;background:#352b1c;border-radius:0 12px 12px 0}blockquote p{margin:4px 0}
code{font-size:.91em;background:#25332d;padding:3px 6px;border-radius:5px;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;margin:24px 0;font-size:16px}td,th{padding:14px 16px;border:1px solid var(--line);text-align:left;vertical-align:top}th{background:#20372d;color:var(--accent)}td{background:var(--panel)}
img{display:block;width:100%;height:auto;margin:28px 0 40px;border:1px solid var(--line);border-radius:16px}footer{color:var(--muted);border-top:1px solid var(--line);font-size:14px}
@media(max-width:650px){body{font-size:16px}header,main,footer{padding-left:18px;padding-right:18px}h1{font-size:28px}h2{font-size:24px}table{font-size:14px}td,th{padding:9px 8px}ol,ul{padding-left:23px}}
@media print{:root{color-scheme:light}body{background:white;color:#171d19;font-size:11pt}strong{color:#171d19}header,main,footer{padding:12px}a{color:#185c48}blockquote,td,th{background:#f0f4f2;color:#171d19}h2,img{break-inside:avoid}}
</style></head><body><header>ELKA NETWORK DIAGNOSTICS / USER GUIDE</header><main>${content}</main><footer>Open Elka.NetworkDiagnostics.exe to start the application. This guide uses example addresses and illustrated screens.</footer></body></html>`;
await fs.writeFile(path.join(root,'START-HERE.html'),html,'utf8');
console.log('START-HERE.html generated from SETUP.md');
