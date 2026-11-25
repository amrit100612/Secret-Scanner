'use strict';
const SecretSweep = (() => {
  const rules = [
    ['GitHub token','High',/\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/],
    ['AWS access key ID','High',/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
    ['Slack token','High',/\bxox[baprs]-[A-Za-z0-9-]{15,}\b/],
    ['Stripe live secret','High',/\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/],
    ['OpenAI API key','High',/\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b/],
    ['Private key','High',/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/],
    ['URL credentials','Medium',/\b[a-z][a-z0-9+.-]*:\/\/[^/?#\s:@\\"'<>`]*:[^/?#\s@\\"'<>`]+@(?:\[[\da-f:.]+\]|[^/?#\s:@\\"'<>`\[\]]+)/i],
  ];
  const sensitive = String.raw`(?:api[_-]?key|token|password|passwd|secret|private[_-]?key|credential|access[_-]?key)`;
  const envAssignment = new RegExp('^\\s*(?:export\\s+)?[\\w-]*'+sensitive+'[\\w-]*\\s*=\\s*(.*)$','i');
  const codeAssignment = new RegExp('(?:^|[^\\w^-])["\']?([\\w-]*'+sensitive+'[\\w-]*)["\']?\\s*[:=]\\s*(["\'])([^\\r\\n]+?)\\2','gi');
  const placeholder = /^(?:$|<[^>]+>|\$\{.*\}|\$[\w]+|\{\{.*\}\}|(?:change[_-]?me|replace[_-]?me|dummy|example|sample|placeholder|redacted|none|null|undefined|todo|xxx+)(?:[-_ ].*)?|your(?:[-_ ].*)?)$/i;
  const browserCredentialModes = new Set(['anonymous','use-credentials','same-origin','include','omit']);
  const urlValue = /^[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+$/i;
  const excluded = /(?:^|\/)(?:\.git|node_modules|\.venv|vendor|dist|coverage)(?:\/|$)|\.(?:png|jpe?g|webp|gif|ico|mp4|mp3|pdf|woff2?|zip|gz|exe|dll|lock)$/i;

  function skip(path,size) {
    if (excluded.test(path)) return 'excluded';
    return size > 2_000_000 ? 'too large' : null;
  }

  const ruleNames = new Set([...rules.map(([rule]) => rule),'Sensitive .env value','Hardcoded credential']);

  function parseAllowlist(source) {
    const config = JSON.parse(source.replace(/^\uFEFF/,''));
    if (!config || !Array.isArray(config.allow)) throw new Error('Expected an allow array.');
    return config.allow.map(entry => {
      if (!entry || typeof entry.path !== 'string' || !entry.path ||
          /[\\\x00-\x1f]/.test(entry.path) || entry.path.split('/').some(part => !part || part === '.' || part === '..') ||
          !ruleNames.has(entry.rule)) throw new Error('Each allow entry requires an exact repository-relative path and a valid rule.');
      return {path:entry.path,rule:entry.rule};
    });
  }

  function scan(path,source,maxFindings=Infinity,allow=[],includeLine=()=>true) {
    const findings = [];
    const env = /(?:^|\/)\.env(?:[.-].*)?$/i.test(path);
    const example = /(?:^|\/)\.env[.-](?:example|sample|template|dist)$/i.test(path);
    const ignored = new Set(allow.filter(entry => entry.path === path).map(entry => entry.rule));
    const lines = source.split(/\r\n|\n|\r/);
    for (let index=0;index<lines.length && findings.length<maxFindings;index++) {
      if (!includeLine(index+1)) continue;
      const line = lines[index];
      const add = (rule,severity) => findings.push({path,line:index+1,rule,severity});
      const known = rules.find(([rule, , pattern]) => !ignored.has(rule) && pattern.test(line));
      if (known) {
        add(...known.slice(0,2));
        continue;
      }
      if (example || /^\s*(?:#|\/\/)/.test(line)) continue;
      const rule = env ? 'Sensitive .env value' : 'Hardcoded credential';
      if (ignored.has(rule)) continue;
      const assignments = env ? [envAssignment.exec(line)] : line.matchAll(codeAssignment);
      for (const assignment of assignments) {
        if (!assignment) continue;
        let value = assignment[env ? 1 : 3];
        value = value.trim().replace(/^"([^"]*)"(?:\s*#.*)?$|^'([^']*)'(?:\s*#.*)?$|(\s+#.*$)/, (_,double,single) => double ?? single ?? '').trim();
        if (!env && assignment[1].toLowerCase() === 'credentials' && browserCredentialModes.has(value)) continue;
        if (value && (env || value.length >= 8) && !placeholder.test(value) && !urlValue.test(value) &&
            !rules.some(([, , pattern]) => pattern.test(value))) {
          add(rule,'Medium');
          break;
        }
      }
    }
    return findings;
  }
  return {scan,skip,parseAllowlist};
})();
if (typeof module !== 'undefined') module.exports = SecretSweep;
