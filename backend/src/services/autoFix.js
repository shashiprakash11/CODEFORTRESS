'use strict';
const axios = require('axios');

// ─── Detect language from file extension ─────────────────────────────────────
function detectLanguage(filePath) {
  if (!filePath) return 'javascript';
  const ext = filePath.split('.').pop().toLowerCase();
  const MAP = {
    js: 'javascript', ts: 'typescript', jsx: 'javascript', tsx: 'typescript',
    py: 'python', rb: 'ruby', php: 'php', java: 'java',
    go: 'go', cs: 'csharp', cpp: 'cpp', c: 'c',
    sh: 'bash', bash: 'bash',
  };
  return MAP[ext] || 'javascript';
}

// ─── Fallback fixes (expanded to cover all 18 SAST rules) ───────────────────
const FIXES = {
  'SQL': `// Fix: Parameterized query — never concatenate user input into SQL
const result = await db.query(
  "SELECT * FROM users WHERE id = ? AND status = ?",
  [userId, status]  // inputs passed separately — database escapes them
);`,

  'Command': `// Fix: execFile with argument array — shell never invoked
const { execFile } = require("child_process");
execFile("convert", [userInput, "output.png"], {
  shell: false,   // CRITICAL: shell:false prevents injection
  timeout: 5000,
  maxBuffer: 1024 * 1024
}, (err, stdout) => { /* handle result */ });`,

  'XSS': `// Fix: textContent instead of innerHTML
element.textContent = userInput;  // browser never parses this as HTML

// If HTML formatting needed, sanitize first:
// import DOMPurify from "dompurify";
// element.innerHTML = DOMPurify.sanitize(userInput, { ALLOWED_TAGS: ["b","i","em"] });`,

  'Path': `// Fix: Resolve and validate path stays inside allowed directory
const path  = require("path");
const BASE  = path.resolve(__dirname, "uploads");
const safe  = path.resolve(BASE, userInput);

if (!safe.startsWith(BASE + path.sep)) {
  return res.status(403).json({ error: "Access denied" });
}
fs.readFile(safe, "utf8", callback);`,

  'Crypto': `// Fix: bcrypt for passwords, SHA-256 for data integrity
const bcrypt = require("bcrypt");
const ROUNDS = 12;

// Hashing a password:
const hash  = await bcrypt.hash(plainPassword, ROUNDS);

// Verifying:
const valid = await bcrypt.compare(inputPassword, hash);

// For non-password integrity checks:
// crypto.createHash("sha256").update(data).digest("hex")`,

  'Debug': `// Fix: Never hardcode debug:true — use environment variable
const isDev = process.env.NODE_ENV === "development";
app.set("debug", isDev);

// .env.production → NODE_ENV=production
// .env.development → NODE_ENV=development`,

  'Redirect': `// Fix: Whitelist allowed redirect destinations
const ALLOWED_REDIRECTS = new Set([
  "https://yourdomain.com",
  "https://dashboard.yourdomain.com",
]);
const target = req.query.redirect || req.body.redirect;
if (!target || !ALLOWED_REDIRECTS.has(target)) {
  return res.status(400).json({ error: "Invalid redirect target" });
}
res.redirect(302, target);`,

  'Prototype': `// Fix: Sanitize keys — reject prototype-polluting keys
const BANNED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function safeMerge(target, source) {
  for (const [k, v] of Object.entries(source)) {
    if (BANNED_KEYS.has(k)) continue;
    target[k] = v;
  }
  return target;
}
// Also consider: const obj = Object.create(null) for pure data maps`,

  'JWT': `// Fix: Never hardcode JWT secret — load from environment
const jwt = require("jsonwebtoken");

// ❌ WRONG: jwt.sign(payload, "mysecret")
// ✅ CORRECT:
const SECRET = process.env.JWT_SECRET;
if (!SECRET) throw new Error("JWT_SECRET not set in environment");

const token    = jwt.sign(payload, SECRET, { expiresIn: "1h", algorithm: "HS256" });
const verified = jwt.verify(incoming, SECRET, { algorithms: ["HS256"] });

// Generate secret: openssl rand -hex 64`,

  'NoSQL': `// Fix: Sanitize MongoDB query — never pass req.body directly
const mongoSanitize = require("express-mongo-sanitize");
app.use(mongoSanitize());  // strips $ and . from req.body globally

// Or manually validate query shape:
const { username } = req.body;
if (typeof username !== "string") return res.status(400).json({ error: "Invalid input" });
const user = await User.findOne({ username });  // safe — typed string`,

  'SSRF': `// Fix: Validate and block private IP ranges
const { URL } = require("url");
const ipRangeCheck = require("ip-range-check");

const BLOCKED = ["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12",
                 "192.168.0.0/16","169.254.0.0/16","::1/128"];

async function safeRequest(rawUrl) {
  const parsed = new URL(rawUrl);
  if (BLOCKED.some(range => ipRangeCheck(parsed.hostname, range))) {
    throw new Error("Request to internal network blocked");
  }
  return axios.get(rawUrl, { timeout: 5000 });
}`,

  'Cookie': `// Fix: Set Secure, HttpOnly, SameSite on all session cookies
res.cookie("session", sessionToken, {
  httpOnly: true,           // JS cannot read this cookie (blocks XSS theft)
  secure:   true,           // HTTPS only
  sameSite: "strict",       // blocks CSRF
  maxAge:   60 * 60 * 1000, // 1 hour
  path:     "/",
});`,

  'Logging': `// Fix: Never log passwords, tokens, or PII
// ❌ WRONG:
// console.log("Login attempt:", { username, password });

// ✅ CORRECT — log only safe metadata:
console.log("Login attempt:", {
  username,
  ip:        req.ip,
  userAgent: req.headers["user-agent"],
  timestamp: new Date().toISOString(),
  // password deliberately omitted
});`,

  'Randomness': `// Fix: crypto.randomBytes for secure tokens — not Math.random()
const crypto = require("crypto");

// ❌ WRONG: Math.random() is predictable
// ✅ CORRECT:
const token  = crypto.randomBytes(32).toString("hex");   // 64-char hex token
const otpNum = crypto.randomInt(100000, 999999);          // secure 6-digit OTP`,

  'Auth': `// Fix: Add authentication middleware before sensitive routes
const jwt = require("jsonwebtoken");

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Apply to all admin routes:
router.use("/admin", requireAuth);
router.use("/dashboard", requireAuth);`,

  'RateLimit': `// Fix: Apply rate limiting to auth endpoints
const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max:      10,               // max 10 attempts per IP
  message:  { error: "Too many login attempts. Try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders:   false,
});

router.post("/login", loginLimiter, loginHandler);`,

  'Eval': `// Fix: Never eval() user input — use JSON.parse() for data
// ❌ WRONG:
// const result = eval(userCode);

// ✅ For data parsing:
const data = JSON.parse(userInput);  // safe — only parses data, no code

// ✅ For expressions (if truly needed), use a sandboxed parser:
// const { parse } = require("acorn");
// parse(userCode, { ecmaVersion: 2020 });  // AST only, no execution`,

  'default': `// Security Fix Required — General Guidelines
// 1. VALIDATE: Whitelist expected input values, reject everything else
// 2. PARAMETERIZE: Never concatenate user input into SQL or shell commands
// 3. ESCAPE OUTPUT: Use textContent not innerHTML; parameterize queries
// 4. LEAST PRIVILEGE: Minimal permissions for DB users and service accounts
// 5. SECRETS: All keys/passwords in environment variables, never in code
// 6. DEPENDENCIES: Run "npm audit fix" to patch known vulnerable packages
//
// Reference: https://owasp.org/www-project-top-ten/`
};

// ─── Match finding name to fallback key ─────────────────────────────────────
function fallback(findingName) {
  const n = findingName.toLowerCase();
  const MAP = {
    'sql':         'SQL',
    'command':     'Command',
    'xss':         'XSS',
    'cross-site':  'XSS',
    'path':        'Path',
    'traversal':   'Path',
    'crypto':      'Crypto',
    'weak crypto': 'Crypto',
    'debug':       'Debug',
    'redirect':    'Redirect',
    'prototype':   'Prototype',
    'jwt':         'JWT',
    'nosql':       'NoSQL',
    'ssrf':        'SSRF',
    'cookie':      'Cookie',
    'log':         'Logging',
    'random':      'Randomness',
    'auth':        'Auth',
    'rate':        'RateLimit',
    'eval':        'Eval',
    'deserializ':  'Eval',
  };
  for (const [keyword, key] of Object.entries(MAP)) {
    if (n.includes(keyword)) return FIXES[key];
  }
  return FIXES.default;
}

// ─── Sleep helper for retry ───────────────────────────────────────────────────
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// ─── Build prompt ─────────────────────────────────────────────────────────────
function buildPrompt(finding, snippet, language) {
  return [
    `You are a senior security engineer. Fix the ${finding.name} vulnerability below.`,
    `Language: ${language}`,
    `Vulnerability: ${finding.name} (${finding.cwe || 'N/A'})`,
    `Severity: ${finding.severity}`,
    `OWASP: ${finding.owasp || 'N/A'}`,
    `File: ${finding.file}  Line: ${finding.line}`,
    `Vulnerable line: ${finding.lineText || 'N/A'}`,
    '',
    'Surrounding code context:',
    '```' + language,
    snippet,
    '```',
    '',
    'Instructions:',
    '- Provide ONLY the fixed code — no markdown fences, no explanation outside code comments',
    '- Add brief inline comments on each changed line explaining WHY the change fixes the issue',
    '- Keep the same language, style, and surrounding logic',
    '- Fix only the vulnerability — minimal changes',
    '- If environment variables are needed, add a comment showing the .env key name',
  ].join('\n');
}

// ─── Main: generate fix with retry ───────────────────────────────────────────
async function generateFix(finding, fileContent) {
  const apiKey  = process.env.GROQ_API_KEY || process.env.ANTHROPIC_API_KEY;
  const useGroq = !!process.env.GROQ_API_KEY;

  // No API key — return pattern-based fix immediately
  if (!apiKey) {
    return {
      fix:    fallback(finding.name),
      by:     'pattern-engine',
      source: 'fallback'
    };
  }

  // Extract code snippet — 6 lines above, 16 lines below for better context
  const allLines = (fileContent || '').split('\n');
  const start    = Math.max(0, (finding.line || 1) - 6);
  const end      = Math.min(allLines.length, (finding.line || 1) + 16);
  const snippet  = allLines.slice(start, end).join('\n');
  const language = detectLanguage(finding.file);
  const prompt   = buildPrompt(finding, snippet, language);

  // Try AI API with 1 retry on timeout
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      let responseText;

      if (useGroq) {
        // ── Groq API (Llama-3.3-70b) ──
        const { data } = await axios.post(
          'https://api.groq.com/openai/v1/chat/completions',
          {
            model:      'llama-3.3-70b-versatile',
            max_tokens: 700,
            messages:   [
              { role: 'system', content: 'You are a senior security engineer who writes clean, secure code fixes.' },
              { role: 'user',   content: prompt }
            ],
            temperature: 0.1,  // low temp = deterministic, focused output
          },
          {
            headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
            timeout: 25000
          }
        );
        responseText = data.choices?.[0]?.message?.content?.trim();

      } else {
        // ── Anthropic Claude API ──
        const { data } = await axios.post(
          'https://api.anthropic.com/v1/messages',
          {
            model:      'claude-sonnet-4-20250514',
            max_tokens: 700,
            messages:   [{ role: 'user', content: prompt }]
          },
          {
            headers: {
              'x-api-key':         apiKey,
              'anthropic-version': '2023-06-01',
              'content-type':      'application/json'
            },
            timeout: 25000
          }
        );
        responseText = data.content?.[0]?.text?.trim();
      }

      if (!responseText) throw new Error('Empty response from AI');

      // Strip any accidental markdown fences the model added
      const fix = responseText
        .replace(/^```[\w]*\n?/gm, '')
        .replace(/^```$/gm, '')
        .trim();

      return {
        fix,
        by:       useGroq ? 'groq-llama-3.3-70b' : 'claude-sonnet-4',
        source:   'ai',
        language,
        attempt,
      };

    } catch (err) {
      const isTimeout = err.code === 'ECONNABORTED' || err.message?.includes('timeout');
      console.error(`[autoFix] Attempt ${attempt} failed:`, err.response?.data?.error?.message || err.message);

      if (attempt < 2 && isTimeout) {
        await sleep(1500);  // wait 1.5s before retry
        continue;
      }

      // Both attempts failed — return pattern fallback
      return {
        fix:    fallback(finding.name),
        by:     'pattern-engine (AI unavailable)',
        source: 'fallback',
        error:  err.response?.data?.error?.message || err.message
      };
    }
  }
}

module.exports = { generateFix };
