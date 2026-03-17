'use strict';

// Shannon entropy calculation
function entropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const c of Object.values(freq)) {
    const p = c / str.length;
    e -= p * Math.log2(p);
  }
  return Math.round(e * 100) / 100;
}

const SKIP_WORDS = ['example','placeholder','your_','<your','xxx','test123',
  'dummy','changeme','replace','insert','todo','sample','fake','password123',
  'xxxxxxxx','00000000','12345678','aaaaaa'];

function looksReal(val) {
  if (!val || val.length < 10) return false;
  if (SKIP_WORDS.some(w => val.toLowerCase().includes(w))) return false;
  if (/^[a-z_\s]+$/i.test(val)) return false;
  return entropy(val) > 3.2;
}

const PATTERNS = [
  { name: 'AWS Access Key',        re: /AKIA[0-9A-Z]{16}/g,                                            sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'GitHub Personal Token', re: /ghp_[0-9a-zA-Z]{36}/g,                                         sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'GitHub OAuth Token',    re: /gho_[0-9a-zA-Z]{36}/g,                                         sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Stripe Secret Key',     re: /sk_live_[0-9a-zA-Z]{24,}/g,                                    sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Stripe Test Key',       re: /sk_test_[0-9a-zA-Z]{24,}/g,                                    sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'Google API Key',        re: /AIza[0-9A-Za-z\-_]{35}/g,                                      sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'Slack Token',           re: /xoxb-[0-9A-Za-z\-]{50,}/g,                                     sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'RSA Private Key',       re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g,                       sev: 'CRITICAL', cwe: 'CWE-321' },
  { name: 'SSH Private Key',       re: /-----BEGIN OPENSSH PRIVATE KEY-----/g,                          sev: 'CRITICAL', cwe: 'CWE-321' },
  { name: 'SendGrid API Key',      re: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g,                 sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'MongoDB URI',           re: /mongodb(\+srv)?:\/\/[^\s"']+/g,                                 sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'PostgreSQL URI',        re: /postgres(ql)?:\/\/[^\s"']+/g,                                   sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'JWT Token',             re: /eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*/g, sev: 'MEDIUM', cwe: 'CWE-522' },
  { name: 'Generic API Key',       re: /(?:api[_-]?key|apikey)\s*[=:]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi, sev: 'HIGH',  cwe: 'CWE-798', capture: true },
  { name: 'Hardcoded Password',    re: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{8,})["']/gi,        sev: 'HIGH',     cwe: 'CWE-259', capture: true },
  { name: 'Hardcoded Secret',      re: /(?:secret|token)\s*[=:]\s*["']([a-zA-Z0-9_\-]{16,})["']/gi,    sev: 'HIGH',     cwe: 'CWE-798', capture: true },
];

function scanSecrets(content, filePath) {
  const findings = [];
  const lines = content.split('\n');

  for (const p of PATTERNS) {
    try {
      const re = new RegExp(p.re.source, p.re.flags);
      let match;
      while ((match = re.exec(content)) !== null) {
        const matched = match[0];
        const value   = p.capture ? (match[1] || matched) : matched;

        if (p.capture && !looksReal(value)) continue;

        const lineNum  = content.substring(0, match.index).split('\n').length;
        const lineText = lineNum <= lines.length ? lines[lineNum - 1].trim().substring(0, 120) : '';

        findings.push({
          id:           'S-' + Date.now() + '-' + findings.length,
          type:         'SECRET',
          name:         p.name,
          severity:     p.sev,
          cwe:          p.cwe,
          file:         filePath,
          line:         lineNum,
          lineText,
          matchPreview: matched.substring(0, 50) + (matched.length > 50 ? '...' : ''),
          entropy:      entropy(value),
          description:  p.name + ' detected with entropy ' + entropy(value).toFixed(2) + '. Rotate immediately.',
          remediation:  'Move to environment variable. Never commit secrets to git.'
        });
      }
    } catch (_) {}
  }

  return findings;
}

module.exports = { scanSecrets, entropy };
