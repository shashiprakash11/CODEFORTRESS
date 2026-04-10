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

// ─── Fallback fixes (pattern-based, no API needed) ───────────────────────────
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
}, (err, stdout) => { /* handle result */ });`,

  'XSS': `// Fix: textContent instead of innerHTML
element.textContent = userInput;  // browser never parses this as HTML

// If HTML formatting needed, sanitize first:
// import DOMPurify from "dompurify";
// element.innerHTML = DOMPurify.sanitize(userInput);`,

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

const hash  = await bcrypt.hash(plainPassword, 12);
const valid = await bcrypt.compare(inputPassword, hash);

// For non-password integrity:
// crypto.createHash("sha256").update(data).digest("hex")`,

  'Debug': `// Fix: Never hardcode debug:true — use environment variable
const isDev = process.env.NODE_ENV === "development";
app.set("debug", isDev);`,

  'Redirect': `// Fix: Whitelist allowed redirect destinations
const ALLOWED = new Set(["https://yourdomain.com", "https://dashboard.yourdomain.com"]);
const target  = req.query.redirect || req.body.redirect;
if (!target || !ALLOWED.has(target)) {
  return res.status(400).json({ error: "Invalid redirect target" });
}
res.redirect(302, target);`,

  'Prototype': `// Fix: Sanitize keys — reject prototype-polluting keys
const BANNED = new Set(["__proto__", "constructor", "prototype"]);
function safeMerge(target, source) {
  for (const [k, v] of Object.entries(source)) {
    if (!BANNED.has(k)) target[k] = v;
  }
  return target;
}`,

  'JWT': `// Fix: Never hardcode JWT secret — load from environment
const jwt    = require("jsonwebtoken");
const SECRET = process.env.JWT_SECRET;
if (!SECRET) throw new Error("JWT_SECRET not set in environment");

const token    = jwt.sign(payload, SECRET, { expiresIn: "1h" });
const verified = jwt.verify(incoming, SECRET);
// Generate: openssl rand -hex 64`,

  'NoSQL': `// Fix: Sanitize MongoDB query — never pass req.body directly
const mongoSanitize = require("express-mongo-sanitize");
app.use(mongoSanitize());  // strips $ and . from req.body globally

// Or validate manually:
if (typeof req.body.username !== "string") return res.status(400).end();
const user = await User.findOne({ username: req.body.username });`,

  'SSRF': `// Fix: Validate and block private IP ranges
const { URL } = require("url");
const BLOCKED  = ["127.","10.","192.168.","169.254.","0.0.0.0","::1"];

async function safeRequest(rawUrl) {
  const parsed = new URL(rawUrl);
  if (BLOCKED.some(r => parsed.hostname.startsWith(r))) {
    throw new Error("Request to internal network blocked");
  }
  return axios.get(rawUrl, { timeout: 5000 });
}`,

  'Cookie': `// Fix: Set Secure, HttpOnly, SameSite on all session cookies
res.cookie("session", sessionToken, {
  httpOnly: true,
  secure:   true,
  sameSite: "strict",
  maxAge:   60 * 60 * 1000,
});`,

  'Logging': `// Fix: Never log passwords, tokens, or PII
// ❌ WRONG: console.log("Login:", { username, password });
// ✅ CORRECT:
console.log("Login attempt:", {
  username,
  ip:        req.ip,
  timestamp: new Date().toISOString(),
  // password deliberately omitted
});`,

  'Randomness': `// Fix: crypto.randomBytes — not Math.random()
const crypto = require("crypto");
const token  = crypto.randomBytes(32).toString("hex");   // secure token
const otp    = crypto.randomInt(100000, 999999);          // secure OTP`,

  'RateLimit': `// Fix: Apply rate limiting to auth endpoints
const rateLimit = require("express-rate-limit");
const limiter   = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      10,
  message:  { error: "Too many attempts. Try again in 15 minutes." },
});
router.post("/login", limiter, loginHandler);`,

  'Eval': `// Fix: Never eval() user input
// ❌ WRONG: eval(userCode)
// ✅ For data: JSON.parse(userInput)
// ✅ For expressions: use a sandboxed AST parser`,

  'default': `// Security Fix Required — General Guidelines
// 1. VALIDATE: Whitelist expected input values
// 2. PARAMETERIZE: Never concatenate user input into SQL or shell commands
// 3. ESCAPE OUTPUT: textContent not innerHTML
// 4. SECRETS: All keys in environment variables, never in code
// 5. DEPENDENCIES: Run "npm audit fix"
// Ref: https://owasp.org/www-project-top-ten/`,
};

// ─── Match finding name to fallback key ──────────────────────────────────────
function fallback(findingName) {
  const n = findingName.toLowerCase();
  const MAP = {
    'sql':        'SQL',      'command':   'Command',
    'xss':        'XSS',      'cross-site':'XSS',
    'path':       'Path',     'traversal': 'Path',
    'crypto':     'Crypto',   'weak cryp': 'Crypto',
    'debug':      'Debug',    'redirect':  'Redirect',
    'prototype':  'Prototype','jwt':       'JWT',
    'nosql':      'NoSQL',    'ssrf':      'SSRF',
    'cookie':     'Cookie',   'log':       'Logging',
    'random':     'Randomness','rate':     'RateLimit',
    'eval':       'Eval',     'deserializ':'Eval',
  };
  for (const [keyword, key] of Object.entries(MAP)) {
    if (n.includes(keyword)) return FIXES[key];
  }
  return FIXES.default;
}

// ─── Sleep for retry ──────────────────────────────────────────────────────────
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ─── Build AI prompt ──────────────────────────────────────────────────────────
function buildPrompt(finding, snippet, language) {
  return [
    `You are a senior security engineer. Fix the ${finding.name} vulnerability below.`,
    `Language: ${language}`,
    `Vulnerability: ${finding.name} (${finding.cwe || 'N/A'})`,
    `Severity: ${finding.severity}`,
    `File: ${finding.file}  Line: ${finding.line}`,
    `Vulnerable line: ${finding.lineText || 'N/A'}`,
    '',
    'Surrounding code:',
    '```' + language,
    snippet,
    '```',
    '',
    'Rules:',
    '- Provide ONLY the fixed code, no markdown fences',
    '- Add brief inline comments explaining each security change',
    '- Keep same language and style',
    '- Minimal changes — fix only the vulnerability',
  ].join('\n');
}

// ─── Main generateFix ─────────────────────────────────────────────────────────
async function generateFix(finding, fileContent) {
  // Read API keys from environment — never hardcoded
  const groqKey      = process.env.GROQ_API_KEY;
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  const apiKey       = groqKey || anthropicKey;
  const useGroq      = !!groqKey;

  // No API key available — return pattern-based fix
  if (!apiKey) {
    console.log('[autoFix] No API key found — using pattern fallback');
    return { fix: fallback(finding.name), by: 'pattern-engine', source: 'fallback' };
  }

  // Build code snippet — 6 lines above, 16 lines below
  const allLines = (fileContent || '').split('\n');
  const start    = Math.max(0, (finding.line || 1) - 6);
  const end      = Math.min(allLines.length, (finding.line || 1) + 16);
  const snippet  = allLines.slice(start, end).join('\n');
  const language = detectLanguage(finding.file);
  const prompt   = buildPrompt(finding, snippet, language);

  // Try with 1 retry on timeout
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      let responseText;

      if (useGroq) {
        // ── Groq API (Llama-3.3-70b) ─────────────────────────────────────────
        const { data } = await axios.post(
          'https://api.groq.com/openai/v1/chat/completions',
          {
            model:       'llama-3.3-70b-versatile',
            max_tokens:  700,
            temperature: 0.1,
            messages: [
              { role: 'system', content: 'You are a senior security engineer. Write clean, secure code fixes only.' },
              { role: 'user',   content: prompt },
            ],
          },
          {
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'Content-Type':  'application/json',
            },
            timeout: 25000,
          }
        );
        responseText = data.choices?.[0]?.message?.content?.trim();

      } else {
        // ── Anthropic Claude API ──────────────────────────────────────────────
        const { data } = await axios.post(
          'https://api.anthropic.com/v1/messages',
          {
            model:      'claude-sonnet-4-20250514',
            max_tokens: 700,
            messages:   [{ role: 'user', content: prompt }],
          },
          {
            headers: {
              'x-api-key':         apiKey,
              'anthropic-version': '2023-06-01',
              'content-type':      'application/json',
            },
            timeout: 25000,
          }
        );
        responseText = data.content?.[0]?.text?.trim();
      }

      if (!responseText) throw new Error('Empty response from AI');

      // Strip accidental markdown fences
      const fix = responseText
        .replace(/^```[\w]*\n?/gm, '')
        .replace(/^```$/gm, '')
        .trim();

      console.log(`[autoFix] Fix generated via ${useGroq ? 'Groq' : 'Claude'} (attempt ${attempt})`);
      return {
        fix,
        by:       useGroq ? 'groq-llama-3.3-70b' : 'claude-sonnet-4',
        source:   'ai',
        language,
      };

    } catch (err) {
      const isTimeout = err.code === 'ECONNABORTED' || (err.message || '').includes('timeout');
      console.error(`[autoFix] Attempt ${attempt} failed:`, err.response?.data?.error?.message || err.message);

      if (attempt < 2 && isTimeout) {
        await sleep(1500);
        continue;
      }

      return {
        fix:    fallback(finding.name),
        by:     'pattern-engine (AI unavailable)',
        source: 'fallback',
        error:  err.response?.data?.error?.message || err.message,
      };
    }
  }
}

module.exports = { generateFix };
