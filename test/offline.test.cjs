const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {createHash}=require('node:crypto');
const vm=require('node:vm');
const html=fs.readFileSync('dist/secret-sweep.html','utf8');
const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match=>match[1]);
test('offline page authorizes the exact browser-normalized CSS and scripts',()=>{
  assert.equal(scripts.length,2);
  for(const value of [...scripts,html.match(/<style>([\s\S]*?)<\/style>/)[1]]){
    const hash=createHash('sha256').update(value.replace(/\r\n?/g,'\n')).digest('base64');
    assert.ok(html.includes("'sha256-"+hash+"'"));
  }
});
test('demo, severity and export produce the expected redacted results',async()=>{
  const element=()=>({value:'',children:[],handlers:{},addEventListener(n,f){this.handlers[n]=f},append(v){this.children.push(v)},replaceChildren(...v){this.children=v},insertCell(){const cell=element();this.append(cell);return cell},click(){this.clicked=true}});
  const map=Object.fromEntries([...html.matchAll(/ id="([^"]+)"/g)].map(match=>[match[1],element()]));
  let exported;
  const document={getElementById:id=>map[id],createDocumentFragment:element,createElement:element};
  const context=vm.createContext({document,File,Blob,URL:{createObjectURL(blob){exported=blob;return 'blob:test'},revokeObjectURL(){}},setTimeout:()=>{}});
  scripts.forEach(script=>vm.runInContext(script,context));
  await map.demo.handlers.click();
  assert.equal(map.findings.hidden,false);
  assert.equal(map.export.disabled,false);
  assert.equal(map.rows.children[0].children.length,3);
  map.severity.value='High';
  map.severity.handlers.change();
  assert.equal(map.rows.children[0].children.length,2);
  map.export.handlers.click();
  const report=await exported.text();
  assert.equal(JSON.parse(report).findings.length,3);
  assert.doesNotMatch(report,/ghp_|local-demo-123/);
});
