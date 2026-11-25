const fs=require('node:fs');
const {createHash}=require('node:crypto');
const read=name=>fs.readFileSync('public/'+name,'utf8').replace(/^\uFEFF/,'').replace(/\r\n?/g,'\n').trimEnd();
const css=read('style.css');
const scripts=['scanner.js','app.js'].map(read);
const hash=value=>"'sha256-"+createHash('sha256').update(value).digest('base64')+"'";
const page=read('index.html')
  .replace("script-src 'self'; style-src 'self'","script-src "+scripts.map(hash).join(' ')+"; style-src "+hash(css))
  .replace('<link rel="stylesheet" href="style.css">','<style>'+css+'</style>')
  .replace(/<script defer src="scanner.js"><\/script>\s*<script defer src="app.js"><\/script>/,'')
  .replace('</body>',()=>scripts.map(script=>'<script>'+script+'</script>').join('\n')+'\n</body>');
fs.mkdirSync('dist',{recursive:true});
fs.writeFileSync('dist/secret-sweep.html',page);
