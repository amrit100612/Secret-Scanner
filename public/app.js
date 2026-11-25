'use strict';
const byId = id => document.getElementById(id);
const controls = ['folder-btn','files-btn','demo'].map(byId);
const drop = byId('drop');
const severity = byId('severity');
const status = byId('status');
const limit = 1000;
let findings = [];
let scanning = false;
let loadedAllowlist = null;
let loadingAllowlist = false;
const allowStatus = byId('allow-status');
const allowButton = byId('allow-btn');
const allowClear = byId('allow-clear');
const allowFile = byId('allow-file');
const configName = '.secretsweep.json';

async function readAllowlist(file) {
  if (file.size > 2_000_000) throw new Error('Allowlist exceeds 2 MB.');
  return SecretSweep.parseAllowlist(await file.text());
}

allowButton.addEventListener('click',() => allowFile.click());
allowFile.addEventListener('change',async () => {
  const file = allowFile.files[0];
  allowFile.value = '';
  if (!file || scanning || loadingAllowlist) return;
  loadingAllowlist = true;
  try {
    loadedAllowlist = await readAllowlist(file);
    allowStatus.textContent = loadedAllowlist.length + ' allowlist entries loaded for the next scan.';
  } catch {
    loadedAllowlist = null;
    allowStatus.textContent = 'Invalid allowlist. Use an allow array with exact paths and rule names.';
  } finally {
    loadingAllowlist = false;
    allowClear.disabled = loadedAllowlist === null;
  }
});
allowClear.addEventListener('click',() => {
  loadedAllowlist = null;
  allowClear.disabled = true;
  allowStatus.textContent = 'Manual allowlist cleared. Folder scans still check their root config.';
});

function renderRows() {
  const fragment = document.createDocumentFragment();
  const selection = findings.filter(item => !severity.value || item.severity === severity.value);
  for (const item of selection) {
    const row = document.createElement('tr');
    const badge = document.createElement('span');
    badge.className = 'badge ' + item.severity.toLowerCase();
    badge.textContent = item.severity;
    row.insertCell().append(badge);
    for (const value of [item.rule,item.path,item.line]) row.insertCell().textContent = value;
    fragment.append(row);
  }
  byId('rows').replaceChildren(fragment);
  byId('findings').hidden = findings.length === 0;
  byId('no-filter').hidden = selection.length > 0;
}

async function run(files, demo=false) {
  if (scanning || loadingAllowlist || !files.length) return;
  scanning = true;
  findings = [];
  severity.value = '';
  renderRows();
  byId('summary').replaceChildren();
  byId('export').disabled = true;
  for (const control of controls) control.disabled = true;
  let scanned = 0, skipped = 0, unreadable = 0, processed = 0;
  let activeAllowlist = demo ? [] : loadedAllowlist;
  allowButton.disabled = true;
  allowClear.disabled = true;
  status.textContent = 'Scanning ' + files.length + ' selected files…';
  try {
    const config = !demo && files.find(file => file.webkitRelativePath?.split('/').slice(1).join('/') === configName);
    if (activeAllowlist === null && config) {
      try {
        activeAllowlist = await readAllowlist(config);
      } catch {
        status.textContent = 'Invalid .secretsweep.json. Fix the config before scanning this folder.';
        return;
      }
    }
    for (const file of files) {
      if (findings.length >= limit) break;
      if (++processed % 40 === 0) {
        status.textContent = 'Processing file ' + processed + ' of ' + files.length + '…';
        await new Promise(resolve => setTimeout(resolve,0));
      }
      const path = file.webkitRelativePath || file.name;
      const relative = file.webkitRelativePath ? path.slice(path.indexOf('/')+1) : path;
      if (relative === configName || SecretSweep.skip(path,file.size)) { skipped++; continue; }
      try {
        const source = await file.text();
        if (source.includes('\0') || source.includes('\uFFFD')) { skipped++; continue; }
        for (const match of SecretSweep.scan(relative,source,limit-findings.length,activeAllowlist ?? [])) {
          findings.push({...match,path});
        }
        scanned++;
      } catch {
        unreadable++;
      }
    }
    const stats = [scanned + ' scanned', skipped + ' skipped', findings.length + ' findings'];
    if (unreadable) stats.push(unreadable + ' unreadable');
    for (const stat of stats) {
      const item = document.createElement('span');
      item.textContent = stat;
      byId('summary').append(item);
    }
    status.textContent = findings.length >= limit
      ? 'Stopped at 1,000 findings. Scan a smaller folder to see the remaining results.'
      : scanned === 0 ? 'No readable text files were scanned.'
      : findings.length ? 'Review the matched lines in your local editor.' : 'No matches for the active rules in the scanned files.';
    renderRows();
    byId('export').disabled = false;
  } finally {
    scanning = false;
    allowButton.disabled = false;
    allowClear.disabled = loadedAllowlist === null;
    for (const control of controls) control.disabled = false;
  }
}

for (const name of ['folder','files']) {
  const input = byId(name);
  byId(name + '-btn').addEventListener('click',() => input.click());
  input.addEventListener('change',() => {
    const selection = Array.from(input.files);
    input.value = '';
    run(selection);
  });
}

for (const event of ['dragenter','dragover']) drop.addEventListener(event, e => {
  e.preventDefault();
  if (!scanning) drop.classList.add('active');
});
drop.addEventListener('dragleave', e => {
  if (!drop.contains(e.relatedTarget)) drop.classList.remove('active');
});
drop.addEventListener('drop', e => {
  e.preventDefault();
  drop.classList.remove('active');
  const items = Array.from(e.dataTransfer.items);
  if (items.some(item => item.webkitGetAsEntry?.()?.isDirectory)) {
    if (!scanning) status.textContent = 'Use Choose folder to scan a directory.';
    return;
  }
  run(Array.from(e.dataTransfer.files));
});

byId('demo').addEventListener('click',() => run([
  new File(['PORT=3000\nDB_PASSWORD=local-demo-123\n'],'demo/.env'),
  new File(['// Demo fixture\nconst token = "ghp_' + 'A'.repeat(36) + '";\n'],'demo/src/config.js'),
  new File(['-----BEGIN OPENSSH PRIVATE KEY-----\n'],'demo/fixture.pem'),
  new File(['API_KEY=your_api_key_here\n'],'demo/.env.example')
],true));
severity.addEventListener('change',renderRows);
byId('export').addEventListener('click',() => {
  const url = URL.createObjectURL(new Blob([JSON.stringify({findings},null,2)],{type:'application/json'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'secret-sweep-report.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url),1000);
});
