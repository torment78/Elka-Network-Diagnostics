// Regenerate the guide's original vector illustrations and PNG exports.
// Requires sharp; an optional first argument supplies its module path.
const fs = require('node:fs/promises');
const path = require('node:path');
const sharp = require(process.argv[2] || 'sharp');
const root = path.resolve(__dirname, '..', 'docs', 'images');
const c = { bg: '#101615', card: '#192321', line: '#34443f', ink: '#f1f6f3', muted: '#b5c6be', green: '#75dcc0', dark: '#102d24', amber: '#f3c878' };
const esc = v => String(v).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const rect = (x,y,w,h,fill=c.card,stroke=c.line,r=18) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}" fill="${fill}" stroke="${stroke}"/>`;
const text = (x,y,value,size=24,fill=c.ink,weight=400) => `<text x="${x}" y="${y}" fill="${fill}" font-size="${size}" font-weight="${weight}">${esc(value)}</text>`;
const lines = (x,y,values,size=24,fill=c.muted,spacing=35) => values.map((v,i)=>text(x,y+i*spacing,v,size,fill)).join('');
const button = (x,y,w,label,enabled=true) => rect(x,y,w,58,enabled?c.green:'#303c37',enabled?c.green:c.line,12)+text(x+20,y+38,label,24,enabled?c.dark:'#8c9e94',650);
const circle = (x,y,n) => `<circle cx="${x}" cy="${y}" r="23" fill="${c.green}"/>`+text(x-7,y+8,n,25,c.dark,700);
const arrow = (x1,y1,x2,y2,color=c.green) => `<path d="M${x1} ${y1} L${x2} ${y2}" stroke="${color}" stroke-width="4" fill="none" marker-end="url(#arrow)"/>`;
const field = (x,y,label,value) => text(x,y,label,19,c.muted,600)+rect(x,y+13,464,57,'#111b17',c.line,10)+text(x+18,y+51,value,26,c.ink,600);
function canvas(title, subtitle, height, content) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="${height}" viewBox="0 0 1280 ${height}" role="img" aria-label="${esc(title)}">
  <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10Z" fill="${c.green}"/></marker></defs>
  <rect width="1280" height="${height}" fill="${c.bg}"/>
  <g font-family="Segoe UI, Arial, sans-serif">${text(48,52,'ELKA NETWORK DIAGNOSTICS  /  QUICK GUIDE',18,c.green,650)}
  ${text(48,105,title,38,c.ink,700)}${text(48,146,subtitle,24,c.muted)}${content}
  ${text(48,height-26,'Illustrated guide • Example data • Follow the matching labels in your app',17,c.muted)}</g></svg>`;
}
function pairing() {
  let s='';
  for (const [x,name,local,other] of [[48,'PC A','192.168.1.20','192.168.1.30'],[676,'PC B','192.168.1.30','192.168.1.20']]) {
    s+=rect(x,184,556,462)+text(x+30,227,name,30,c.green,700);
    s+=field(x+30,268,'THIS PC — SELECT YOUR LAN ADAPTER',local);
    s+=field(x+30,368,'PEER CONNECTION — ENTER THE OTHER PC',other);
    s+=field(x+30,468,'PAIRING CODE — MATCH ON BOTH PCs','The same complete code');
    s+=button(x+30,563,225,'Start endpoint')+text(x+283,600,'Click on BOTH',22,c.green,600);
  }
  s+=rect(48,678,1184,139,c.dark,c.line)+circle(84,719,'1')+text(120,728,'Each PC enters the other PC’s address.',26,c.ink,600);
  s+=text(78,775,'Copy one code to both PCs. Match ports: control 47830 • test 47831.',25,c.muted);
  return canvas('Pair the two computers','Match the code and ports. The peer address is different on each PC.',865,s);
}
function shared() {
  let s=rect(48,184,520,238)+text(78,226,'PC A',28,c.green,700)+button(78,252,253,'Check both PCs')+circle(372,281,'1');
  s+=lines(78,350,['Click ONCE on either paired PC.','You choose which PC starts.'],25);
  s+=rect(712,184,520,238)+text(742,226,'PC B',28,c.green,700)+text(742,282,'Joins automatically',29,c.ink,650);
  s+=lines(742,340,['Keep this app open and paired.','No second click is needed.'],24);
  s+=arrow(589,286,692,286);
  s+=rect(48,454,1184,311)+text(78,500,'Both screens show progress and the same four results',29,c.ink,650);
  const rows=[['UDP','PC A → PC B'],['UDP','PC B → PC A'],['TCP','PC A → PC B'],['TCP','PC B → PC A']];
  rows.forEach(([protocol,direction],i)=>{
    let y=525+i*53;s+=rect(78,y,1124,46,'#111b17',c.line,8)+text(96,y+31,protocol,22,c.green,650)+text(220,y+31,direction,23)+text(630,y+31,'200 / 200 verified',23)+text(1017,y+31,'Delivered',22,c.green);
  });
  s+=text(48,812,'Example passing result. Read the next-step suggestion before a full scan.',24,c.muted);
  return canvas('One click checks BOTH PCs','This quick check tests UDP and TCP in both directions.',862,s);
}
function fullScans() {
  let s=rect(48,177,1184,76,'#352b1c','#735c32')+text(78,225,'NEVER run “Run all checks” on both PCs at the same time.',29,c.amber,700);
  s+=circle(71,300,'1')+text(108,310,'First: inspect the suggested PC (PC A in this example)',28,c.ink,650);
  s+=rect(48,337,556,203)+text(78,381,'PC A — YOU ARE HERE',24,c.green,700)+button(78,405,235,'Run all checks');
  s+=text(78,507,'Stay here and answer permission prompts.',24);
  s+=rect(676,337,556,203)+text(706,381,'PC B — LEAVE IDLE',24,c.amber,700);
  s+=lines(706,427,['Keep Elka open and paired.','Do not start a scan, test or capture.'],24);
  s+=arrow(640,557,640,592);
  s+=rect(48,610,1184,117,c.dark,c.line)+text(78,653,'WAIT for the full scan to finish',28,c.green,700);
  s+=text(78,694,'Answer prompts. Wait for recommendations and available run buttons.',24,c.ink);
  s+=circle(71,785,'2')+text(108,795,'Then: go to the OTHER PC and run its full scan',28,c.ink,650);
  s+=rect(48,823,556,203)+text(78,866,'PC A — LEAVE IDLE',24,c.amber,700);
  s+=lines(78,913,['Keep Elka open and paired.','Do not start another test.'],24);
  s+=rect(676,823,556,203)+text(706,866,'PC B — YOU ARE HERE',24,c.green,700)+button(706,890,235,'Run all checks');
  s+=text(706,992,'Stay here and answer its prompts.',24);
  s+=text(48,1082,'No address swap. No role change. Save a report from each PC.',25,c.muted);
  return canvas('Full scans: ONE computer at a time','Each scan collects Windows evidence on the PC where you click.',1135,s);
}
function waiting() {
  let s=rect(48,190,556,325)+text(78,238,'STILL WORKING',26,c.amber,700);
  s+=lines(78,288,['A test or capture is running,','or a permission window needs you.'],25);
  s+=button(78,367,235,'Run all checks',false)+text(78,468,'Keep waiting. Check for prompts.',25,c.amber,600);
  s+=rect(676,190,556,325)+text(706,238,'READY FOR THE NEXT SCAN',26,c.green,700);
  s+=lines(706,288,['Final recommendations are displayed.','The run buttons are available again.'],25);
  s+=button(706,367,235,'Run all checks')+text(706,468,'Read the result, then continue.',25,c.green,600);
  s+=rect(48,553,1184,151,c.dark,c.line)+text(78,603,'Finished does not mean every result turns green.',31,c.ink,650);
  s+=lines(78,648,['Amber or red findings can remain. Read the status and recommendations;','a cancelled or incomplete scan needs review before you move on.'],24,c.muted,33);
  return canvas('Wait for completion, not a colour change','The first passing traffic results are not the end of a full scan.',756,s);
}
(async()=>{
  await fs.mkdir(root,{recursive:true});
  for (const [name,draw] of [['pairing',pairing],['check-both-pcs',shared],['full-scans-one-at-a-time',fullScans],['wait-for-completion',waiting]]) {
    const svg=draw(); await fs.writeFile(path.join(root,name+'.svg'),svg,'utf8');
    await sharp(Buffer.from(svg)).png().toFile(path.join(root,name+'.png'));
    console.log(name+'.png');
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
