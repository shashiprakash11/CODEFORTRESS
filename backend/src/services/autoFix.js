'use strict';
const axios = require('axios');

const FIXES = {
  'SQL':        '// Fix: Use parameterized query\nconst result = await db.query(\n  "SELECT * FROM users WHERE id = ?",\n  [userId]  // user input as separate parameter — safe\n);',
  'Command':    '// Fix: Use execFile with argument array\nconst { execFile } = require("child_process");\nexecFile("convert", [userInput, "output.png"], {\n  shell: false,  // CRITICAL: never shell:true with user input\n  timeout: 5000\n});',
  'XSS':        '// Fix: Use textContent instead of innerHTML\nelement.textContent = userInput;  // safe — no HTML parsing\n\n// If you need HTML formatting, use DOMPurify:\n// const clean = DOMPurify.sanitize(userInput);\n// element.innerHTML = clean;',
  'Path':       '// Fix: Validate path stays within base directory\nconst path = require("path");\nconst BASE_DIR = path.resolve(__dirname, "uploads");\nconst safePath = path.resolve(BASE_DIR, userInput);\nif (!safePath.startsWith(BASE_DIR)) {\n  return res.status(403).json({ error: "Invalid path" });\n}\nfs.readFile(safePath, "utf8", callback);',
  'Crypto':     '// Fix: Use bcrypt for passwords, SHA-256 for integrity\nconst bcrypt = require("bcrypt");\n\n// For passwords:\nconst hash = await bcrypt.hash(password, 12);\nconst valid = await bcrypt.compare(input, hash);\n\n// For data integrity (not passwords):\nconst hash = crypto.createHash("sha256").update(data).digest("hex");',
  'Debug':      '// Fix: Use environment-based debug flag\napp.set("debug", process.env.NODE_ENV === "development");\n\n// In your .env file:\n// NODE_ENV=production  (for deployment)\n// NODE_ENV=development (for local dev)',
  'Redirect':   '// Fix: Whitelist allowed redirect destinations\nconst ALLOWED = ["https://myapp.com", "https://dashboard.myapp.com"];\nconst target = req.query.redirect;\nif (!ALLOWED.includes(target)) {\n  return res.status(400).json({ error: "Invalid redirect" });\n}\nres.redirect(target);',
  'Prototype':  '// Fix: Sanitize keys before merging objects\nfunction safeAssign(target, source) {\n  const BANNED = ["__proto__", "constructor", "prototype"];\n  for (const [key, val] of Object.entries(source)) {\n    if (!BANNED.includes(key)) target[key] = val;\n  }\n  return target;\n}',
  'default':    '// Security Fix Required\n// Follow these principles:\n// 1. Validate ALL user inputs — whitelist expected values\n// 2. Use parameterized queries — never string concat in SQL\n// 3. Escape output — textContent not innerHTML\n// 4. Principle of least privilege — minimal permissions\n// 5. Keep dependencies updated — npm audit fix\n// Ref: https://owasp.org/www-project-top-ten/'
};

function fallback(name) {
  const n = name.toLowerCase();
  for (const [key, fix] of Object.entries(FIXES)) {
    if (key !== 'default' && n.includes(key.toLowerCase())) return fix;
  }
  return FIXES.default;
}

async function generateFix(finding, fileContent) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { fix: fallback(finding.name), by: 'pattern-engine' };

  const snippet = (fileContent || '').split('\n')
    .slice(Math.max(0, (finding.line || 1) - 4), (finding.line || 1) + 12)
    .join('\n');

  const prompt = [
    'You are a senior security engineer. Fix this vulnerability with minimal code changes.',
    '',
    'Vulnerability: ' + finding.name,
    'CWE: ' + (finding.cwe || 'N/A'),
    'Severity: ' + finding.severity,
    'File: ' + finding.file + ' Line ' + finding.line,
    'Vulnerable code: ' + (finding.lineText || 'N/A'),
    '',
    'Context:',
    '```',
    snippet,
    '```',
    '',
    'Provide ONLY the fixed code with brief inline comments explaining each change.',
    'Keep the same language and coding style. No markdown. No explanation outside the code.'
  ].join('\n');

  try {
    const { data } = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model:      'claude-sonnet-4-20250514',
        max_tokens: 600,
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
    const fix = data.content?.[0]?.text?.trim() || fallback(finding.name);
    return { fix, by: 'claude-sonnet-4' };
  } catch (err) {
    console.error('Claude API error:', err.response?.data || err.message);
    return { fix: fallback(finding.name), by: 'pattern-engine (claude unavailable)' };
  }
}

module.exports = { generateFix };
