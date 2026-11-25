const {test}=require('node:test');
const assert=require('node:assert/strict');
const {scan,skip}=require('../public/scanner.js');
test('provider keys keep only rule and position',()=>{
  const key='ghp_'+'A'.repeat(36);
  const found=scan('src/config.js','\nconst token="'+key+'";');
  assert.deepEqual(found,[{path:'src/config.js',line:2,rule:'GitHub token',severity:'High'}]);
});
test('dotenv assignments catch secrets and ignore placeholders',()=>{
  assert.deepEqual(scan('.env.local','DB_PASSWORD="a synthetic value"\nAPI_KEY=changeme\nAPI_TOKEN=${FROM_ENV}\nPORT=3000'.replace('\\$','$')).map(x=>x.line),[1]);
  assert.deepEqual(scan('.env.example','API_KEY=your_api_key_here'),[]);
  assert.equal(scan('.env.example','API_KEY=ghp_'+'A'.repeat(36)).length,1);
});
test('private key headers and URLs with passwords are detected',()=>{
  assert.equal(scan('test.txt','-----BEGIN OPENSSH PRIVATE KEY-----')[0].rule,'Private key');
  assert.equal(scan('test.txt','postgres://demo:Pass123@localhost/db')[0].rule,'URL credentials');
});
test('binary, dependency and Git internals are skipped',()=>{
  assert.equal(skip('project/.git/config',1),'excluded');
  assert.equal(skip('project/node_modules/lib.js',1),'excluded');
  assert.equal(skip('file.js',2_000_001),'too large');
  assert.equal(skip('file.png',100),'excluded');
  assert.equal(skip('src/app.js',1),null);
});
