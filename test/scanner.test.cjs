const {test}=require('node:test');
const assert=require('node:assert/strict');
const {scan,skip}=require('../public/scanner.js');
test('provider keys keep only rule and position',()=>{
  const key='ghp_'+'A'.repeat(36);
  const found=scan('src/config.js','\nconst token="'+key+'";');
  assert.deepEqual(found,[{path:'src/config.js',line:2,rule:'GitHub token',severity:'High'}]);
});
test('dotenv assignments catch secrets and ignore placeholders',()=>{
  assert.deepEqual(scan('.env.local','DB_PASSWORD'+'="a synthetic value"\nAPI_KEY=changeme\nAPI_TOKEN=${FROM_ENV}\nPORT=3000'.replace('\\$','$')).map(x=>x.line),[1]);
  assert.deepEqual(scan('.env.example','API_KEY=your_api_key_here'),[]);
  assert.equal(scan('.env.example','API_KEY=ghp_'+'A'.repeat(36)).length,1);
});
test('private key headers and URLs with passwords are detected',()=>{
  assert.equal(scan('test.txt','-----BEGIN'+' OPENSSH PRIVATE KEY-----')[0].rule,'Private key');
  assert.equal(scan('test.txt','postgres:'+'//demo:Pass123@localhost/db')[0].rule,'URL credentials');
});
test('binary, dependency and Git internals are skipped',()=>{
  assert.equal(skip('project/.git/config',1),'excluded');
  assert.equal(skip('project/node_modules/lib.js',1),'excluded');
  assert.equal(skip('file.js',2_000_001),'too large');
  assert.equal(skip('file.png',100),'excluded');
  assert.equal(skip('src/app.js',1),null);
});

test('public URLs with ports, @ handles, query strings and fragments are ignored',()=>{
  const lines = [
    'https://example.com:8443/@profile',
    'https://example.com:8443?email=contact@example.org',
    'https://example.com:8443#contact@example.org',
    'https://example.com?q=contact@example.org',
    'https://example.com#contact@example.org',
    'https://example.com/path:8080/@profile',
    'https://example.com:8443/path @someone',
    'const tokenDocs = "https://example.com/docs";'
  ];
  assert.deepEqual(scan('links.js',lines.join('\n')),[]);
  assert.deepEqual(scan('.env','API_TOKEN_URL=https://example.com/docs'),[]);
});

test('URLs with embedded passwords and known tokens still produce redacted findings',()=>{
  const path = 'links.txt';
  const token = 'ghp_'+'A'.repeat(36);
  const lines = [
    'https:'+'//user:pass%40word@example.com:8443/',
    'https://example.com/?token='+token,
    'https://user@example.com/',
    'https://user:@example.com/'
  ];
  assert.deepEqual(scan(path,lines.join('\n')),[
    {path,line:1,rule:'URL credentials',severity:'Medium'},
    {path,line:2,rule:'GitHub token',severity:'High'}
  ]);
});

test('ignores browser credential modes and shell searches while keeping real assignments',()=>{
  const source = [
    'options.credentials = "anonymous";',
    'const options = { credentials: "same-origin" };',
    "grep '^ELEVENLABS_API_KEY=' \"example.env\" \"config.env\"",
    'const password'+' = "a synthetic password";',
    'const credentials'+' = "a synthetic credential";',
    'options.credentials = "anonymous"; const password'+' = "another synthetic password";'
  ].join('\n');
  assert.deepEqual(scan('example.js',source).map(x=>x.line),[4,5,6]);
});

test('scanner source and shipped demo definitions contain no reportable secrets',()=>{
  const {readFileSync}=require('node:fs');
  const {resolve}=require('node:path');
  for (const path of ['public/app.js','test/scanner.test.cjs']) {
    assert.deepEqual(scan(path,readFileSync(resolve(__dirname,'..',path),'utf8')),[]);
  }
});

test('oversized lines are reported while subsequent lines retain their original positions',()=>{
  const skipped = [];
  const findings = scan('source.js','A'.repeat(4097)+'\n'+'ghp_'+'A'.repeat(36),
    Infinity,[],undefined,line=>skipped.push(line));
  assert.deepEqual(skipped,[1]);
  assert.equal(findings[0].line,2);
});
