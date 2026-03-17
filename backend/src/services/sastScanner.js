'use strict';

const RULES = [
  {
    id: 'SAST-001', name: 'SQL Injection', cwe: 'CWE-89', sev: 'CRITICAL', owasp: 'A03:2021',
    desc: 'User input concatenated directly into SQL query. Enables full database compromise.',
    fix:  'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [id])',
    patterns: [
      /["'`][^"'`]*(SELECT|INSERT|UPDATE|DELETE)[^"'`]*["'`]\s*\+/gi,
      /query\s*\(\s*["'`][^"'`]*(SELECT|INSERT|UPDATE|DELETE)[^"'`]*\$\{/gi,
      /execute\s*\(\s*["'`].*?(SELECT|INSERT|UPDATE|DELETE)/gi,
    ]
  },
  {
    id: 'SAST-002', name: 'Command Injection', cwe: 'CWE-78', sev: 'CRITICAL', owasp: 'A03:2021',
    desc: 'User-controlled data passed to OS shell. Enables remote code execution.',
    fix:  'Use execFile(cmd, [arg1, arg2], {shell:false}) — never exec() with string concat.',
    patterns: [
      /exec\s*\(\s*["'`][^"'`]*["'`]\s*\+/gi,
      /exec\s*\(`[^`]*\$\{/gi,
      /execSync\s*\(`[^`]*\$\{/gi,
    ]
  },
  {
    id: 'SAST-003', name: 'Cross-Site Scripting (XSS)', cwe: 'CWE-79', sev: 'HIGH', owasp: 'A03:2021',
    desc: 'Unescaped user input rendered as HTML. Enables session hijacking and phishing.',
    fix:  'Use element.textContent = input instead of innerHTML. Or use DOMPurify.sanitize().',
    patterns: [
      /innerHTML\s*=\s*(?!["'`])[^;]*(req\.|request\.|params\.|query\.|body\.)/gi,
      /document\.write\s*\([^)]*\+/gi,
      /dangerouslySetInnerHTML.*?\$\{/gi,
    ]
  },
  {
    id: 'SAST-004', name: 'Path Traversal', cwe: 'CWE-22', sev: 'HIGH', owasp: 'A01:2021',
    desc: 'Unvalidated file path allows access outside intended directory.',
    fix:  'Validate: const safe = path.resolve(BASE, input); if(!safe.startsWith(BASE)) throw Error()',
    patterns: [
      /(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|params\.|query\.)/gi,
      /res\.sendFile\s*\([^)]*(?:req\.|params\.|query\.)/gi,
    ]
  },
  {
    id: 'SAST-005', name: 'Weak Cryptography', cwe: 'CWE-327', sev: 'MEDIUM', owasp: 'A02:2021',
    desc: 'MD5 or SHA-1 is cryptographically broken. Should not be used for passwords or integrity.',
    fix:  'Use crypto.createHash("sha256") for data integrity, or bcrypt for passwords.',
    patterns: [
      /createHash\s*\(\s*["']md5['"]/gi,
      /createHash\s*\(\s*["']sha1['"]/gi,
    ]
  },
  {
    id: 'SAST-006', name: 'Insecure Deserialization', cwe: 'CWE-502', sev: 'HIGH', owasp: 'A08:2021',
    desc: 'Deserializing untrusted data can lead to remote code execution.',
    fix:  'Use JSON.parse() for data exchange. Avoid eval(), unserialize(), pickle.loads() on user input.',
    patterns: [
      /eval\s*\(\s*(?!["'`])[^)]*(?:req\.|body\.|params\.)/gi,
      /unserialize\s*\(/gi,
    ]
  },
  {
    id: 'SAST-007', name: 'Debug Mode Enabled', cwe: 'CWE-215', sev: 'MEDIUM', owasp: 'A05:2021',
    desc: 'Debug mode exposes stack traces, source maps, and internal state in production.',
    fix:  'Use: debug: process.env.NODE_ENV === "development"',
    patterns: [
      /debug\s*[:=]\s*true/gi,
      /app\.run\s*\([^)]*debug\s*=\s*True/g,
    ]
  },
  {
    id: 'SAST-008', name: 'Unvalidated Redirect', cwe: 'CWE-601', sev: 'MEDIUM', owasp: 'A01:2021',
    desc: 'Redirect URL taken from user input enables phishing attacks.',
    fix:  'Whitelist allowed redirect URLs. Never redirect to user-supplied URLs directly.',
    patterns: [
      /res\.redirect\s*\([^)]*(?:req\.query|req\.body|req\.params)/gi,
    ]
  },
  {
    id: 'SAST-009', name: 'Prototype Pollution', cwe: 'CWE-1321', sev: 'HIGH', owasp: 'A03:2021',
    desc: 'Attacker-controlled keys merged into Object.prototype affect all objects globally.',
    fix:  'Sanitize keys: reject __proto__, constructor, prototype. Use Object.create(null).',
    patterns: [
      /Object\.assign\s*\(\s*(?:this|prototype|__proto__)/gi,
      /\[.*\]\s*=.*(?:__proto__|constructor\.prototype)/gi,
    ]
  },
  {
    id: 'SAST-010', name: 'SSRF Risk', cwe: 'CWE-918', sev: 'HIGH', owasp: 'A10:2021',
    desc: 'Server-side request made to user-controlled URL. Can access internal services.',
    fix:  'Validate and whitelist URLs. Block private IP ranges (127.x, 10.x, 192.168.x).',
    patterns: [
      /(?:axios\.get|fetch|http\.get|https\.get|request\.get)\s*\(\s*(?:req\.|request\.)/gi,
    ]
  },
];

function scanSAST(content, filePath) {
  const findings = [];
  const lines = content.split('\n');

  for (const rule of RULES) {
    const seenLines = new Set();
    for (const pattern of rule.patterns) {
      try {
        const re = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = re.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          if (seenLines.has(lineNum)) continue;
          seenLines.add(lineNum);
          const lineText = lineNum <= lines.length ? lines[lineNum - 1].trim().substring(0, 120) : '';
          findings.push({
            id:          rule.id + '-' + Date.now() + '-' + findings.length,
            type:        'SAST',
            name:        rule.name,
            severity:    rule.sev,
            cwe:         rule.cwe,
            owasp:       rule.owasp,
            file:        filePath,
            line:        lineNum,
            lineText,
            description: rule.desc,
            remediation: rule.fix
          });
        }
      } catch (_) {}
    }
  }
  return findings;
}

function riskScore(findings) {
  if (!findings.length) return { score: 0, level: 'PASS', label: 'PASS', grade: 'A', criticals: 0, highs: 0, mediums: 0, total: 0 };
  const W = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 0.5 };
  const raw = findings.reduce((a, f) => a + (W[f.severity] || 0.5), 0);
  const score = Math.min(100, Math.round(raw * 2));
  const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs     = findings.filter(f => f.severity === 'HIGH').length;
  let level, label, grade;
  if (criticals > 0 || score >= 80)  { level = 'FAIL'; label = 'FAILED';       grade = 'F'; }
  else if (score >= 50 || highs > 2) { level = 'WARN'; label = 'BLOCK_DEPLOY'; grade = 'D'; }
  else if (score >= 25)              { level = 'WARN'; label = 'WARN';          grade = 'C'; }
  else                               { level = 'PASS'; label = 'PASS';          grade = 'B'; }
  return { score, level, label, grade, criticals, highs, mediums: findings.filter(f => f.severity === 'MEDIUM').length, total: findings.length };
}

function attackPaths(findings, repoName) {
  const paths = [];
  const secrets = findings.filter(f => f.type === 'SECRET');
  const sqli    = findings.filter(f => f.name.includes('SQL'));
  const cmdi    = findings.filter(f => f.name.includes('Command'));
  const xss     = findings.filter(f => f.name.includes('XSS') || f.name.includes('Cross-Site'));

  const yr = new Date().getFullYear();

  secrets.slice(0, 2).forEach((f, i) => paths.push({
    id: 'SEC-ML-XGB-' + yr + '-' + (100 + i),
    cwe: f.cwe, severity: 'CRITICAL',
    title: f.name + ' Enables Unauthorized Access',
    file: f.file, line: f.line, mitre: 'T1552',
    steps: [
      'Attacker discovers ' + f.name + ' in ' + f.file + ' line ' + f.line + ' via public repo.',
      'Extracts credential: ' + (f.matchPreview || f.lineText || 'value detected'),
      'Authenticates against external API using stolen credential.',
      'Gains unauthorized access. Exfiltrates data or performs fraudulent actions.'
    ]
  }));

  sqli.slice(0, 1).forEach((f, i) => paths.push({
    id: 'SEC-ML-GNN-' + yr + '-' + (200 + i),
    cwe: 'CWE-89', severity: 'CRITICAL',
    title: 'SQL Injection Leads to Full Database Compromise',
    file: f.file, line: f.line, mitre: 'T1190',
    steps: [
      'Attacker identifies unsanitized SQL query in ' + f.file + ' line ' + f.line + '.',
      "Injects ' OR 1=1-- payload to bypass authentication check.",
      'Uses UNION SELECT to enumerate all database tables and columns.',
      'Dumps user credentials, PII, session tokens, and payment data.'
    ]
  }));

  cmdi.slice(0, 1).forEach((f, i) => paths.push({
    id: 'SEC-ML-GNN-' + yr + '-' + (300 + i),
    cwe: 'CWE-78', severity: 'CRITICAL',
    title: 'Command Injection Leads to Remote Code Execution',
    file: f.file, line: f.line, mitre: 'T1059',
    steps: [
      'Attacker finds exec() with user-controlled input in ' + f.file + ' line ' + f.line + '.',
      'Injects shell metacharacters into user-controlled parameter.',
      'Executes arbitrary OS commands on the production server.',
      'Establishes persistent reverse shell. Full system compromised.'
    ]
  }));

  xss.slice(0, 1).forEach((f, i) => paths.push({
    id: 'SEC-ML-GNN-' + yr + '-' + (400 + i),
    cwe: 'CWE-79', severity: 'HIGH',
    title: 'Stored XSS Leads to Session Hijacking',
    file: f.file, line: f.line, mitre: 'T1185',
    steps: [
      'Attacker injects malicious script tag into stored input field in ' + f.file + '.',
      'Victim visits affected page — script executes in their browser.',
      'Session cookie exfiltrated to attacker-controlled server.',
      'Attacker hijacks authenticated session. Account fully compromised.'
    ]
  }));

  if (!paths.length) paths.push({
    id: 'SEC-INFO-' + yr + '-001', cwe: 'N/A', severity: 'INFO',
    title: 'No Critical Attack Paths Detected',
    file: '—', line: 0, mitre: 'N/A',
    steps: ['No critical vulnerabilities found in this repository.', 'Continue monitoring future commits.']
  });

  return paths;
}

module.exports = { scanSAST, riskScore, attackPaths };
