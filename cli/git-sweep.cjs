'use strict';
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const {scan,skip,parseAllowlist} = require('../public/scanner.js');

const configPath = '.secretsweep.json';
const maxSize = 2_000_000;
const env = {...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_NO_LAZY_FETCH:'1'};
const [command,...options] = process.argv.slice(2);
const json = options.includes('--json');

function git(...args) {
  try {
    return execFileSync('git',['--no-pager','--literal-pathspecs',...args],{
      env,maxBuffer:64*1024*1024,stdio:['ignore','pipe','pipe']
    });
  } catch {
    throw new Error('Git could not complete '+args[0]+'. Run from a readable local repository.');
  }
}

function text(...args) {
  return git(...args).toString('utf8');
}

function files(raw) {
  const fields = raw.split('\0');
  const entries = [];
  for (let i=0;i+1<fields.length;i+=2) {
    const [,mode,,oid] = fields[i].split(' ');
    if (/^100[0-7]{3}$/.test(mode)) entries.push({path:fields[i+1],oid});
  }
  return entries;
}

function blob(oid) {
  const size = Number(text('cat-file','-s',oid));
  if (size > maxSize) return null;
  const value = text('cat-file','blob',oid);
  return /[\0\uFFFD]/.test(value) ? null : value;
}

function allowlist() {
  try {
    if (command === 'staged') {
      const match = /^100[0-7]{3} ([a-f0-9]+) 0\t/m.exec(text('ls-files','--stage','--',configPath));
      if (!match) return [];
      const value = blob(match[1]);
      if (value === null) throw new Error();
      return parseAllowlist(value);
    }
    if (!fs.existsSync(configPath)) return [];
    const stat = fs.lstatSync(configPath);
    if (!stat.isFile() || stat.size > maxSize) throw new Error();
    return parseAllowlist(fs.readFileSync(configPath,'utf8'));
  } catch {
    throw new Error('Invalid or unreadable '+configPath+'. Use an allow array with exact paths and rule names.');
  }
}

function stagedLines(file) {
  const patch = text('diff','--cached','--no-ext-diff','--no-textconv','--no-color','--text',
    '--no-renames','--no-indent-heuristic','--diff-algorithm=myers','--unified=0','--',file);
  const ranges = Array.from(patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm),
    ([,start,count]) => [Number(start),Number(start)+Number(count ?? 1)]);
  let index = 0;
  return line => {
    while (index < ranges.length && line >= ranges[index][1]) index++;
    return index < ranges.length && line >= ranges[index][0];
  };
}

function inspect(entries,allow,findings,commit,seen,stats) {
  for (const entry of entries) {
    const key = entry.path+'\0'+entry.oid;
    if (seen?.has(key)) continue;
    seen?.add(key);
    const source = skip(entry.path,0) ? null : blob(entry.oid);
    if (source === null) {stats.skipped++;continue;}
    stats.scanned++;
    const matches = scan(entry.path,source,Infinity,allow,commit ? undefined : stagedLines(entry.path));
    for (const match of matches) findings.push(commit ? {...match,commit} : match);
  }
}

function install() {
  const hook = text('rev-parse','--git-path','hooks/pre-commit').trimEnd();
  const quote = value => "'"+value.replaceAll("'","'\\''")+"'";
  const shellPath = value => process.platform === 'win32' ? value.replaceAll('\\','/') : value;
  fs.mkdirSync(path.dirname(hook),{recursive:true});
  try {
    fs.writeFileSync(hook,'#!/bin/sh\nexec '+quote(shellPath(process.execPath))+' '+quote(shellPath(__filename))+' staged\n',{flag:'wx',mode:0o755});
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error('A pre-commit hook already exists. Add this scanner to the existing hook manually.');
    throw new Error('Could not write the pre-commit hook.');
  }
  console.log('Installed '+hook);
}

function main() {
  if (!command || command === '--help') {
    console.log('Usage: node git-sweep.cjs staged|history [--json]\n       node git-sweep.cjs install-hook');
    return;
  }
  if (!['staged','history','install-hook'].includes(command) ||
      options.some(option => option !== '--json') || options.length > 1 ||
      (command === 'install-hook' && options.length)) throw new Error('Invalid command. Run with --help.');
  process.chdir(text('rev-parse','--show-toplevel').trimEnd());
  if (command === 'install-hook') return install();

  const findings = [];
  const stats = {scanned:0,skipped:0};
  const allow = allowlist();
  let shallow = false;
  if (command === 'staged') {
    inspect(files(text('diff','--cached','--raw','--no-abbrev','--no-renames','-z')),allow,findings,null,null,stats);
  } else {
    shallow = text('rev-parse','--is-shallow-repository').trim() === 'true';
    const seen = new Set();
    const head = text('rev-parse','--revs-only','HEAD').trim();
    const commits = text('rev-list','--parents','--reverse','--all',...(head ? [head] : [])).trim();
    for (const row of commits ? commits.split('\n') : []) {
      const [commit,parent] = row.split(' ');
      const changes = text('diff-tree','--root','--no-commit-id','--raw','--no-abbrev','--no-renames','-r','-z',...(parent ? [parent,commit] : [commit]));
      inspect(files(changes),allow,findings,commit,seen,stats);
    }
  }
  const blocked = findings.some(match => match.severity === 'High');
  if (json) console.log(JSON.stringify({command,...stats,shallow,findings},null,2));
  else {
    for (const match of findings) {
      const commit = match.commit ? match.commit.slice(0,12)+' ' : '';
      console.error(commit+JSON.stringify(match.path)+':'+match.line+'  '+match.severity+'  '+match.rule);
    }
    console.error(stats.scanned+' scanned, '+stats.skipped+' skipped, '+findings.length+' findings.');
    if (shallow) console.error('Shallow repository. History is limited to locally available commits.');
  }
  process.exitCode = blocked ? 1 : 0;
}

try { main(); }
catch (error) { console.error(error.message); process.exitCode = 2; }
