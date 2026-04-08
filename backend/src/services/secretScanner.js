'use strict';

// ─── File type filtering ──────────────────────────────────────────────────────
const SCANNABLE_EXTS = [
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.php', '.java', '.go', '.cs', '.cpp', '.c',
  '.env', '.config', '.conf', '.cfg', '.ini', '.toml', '.yaml', '.yml',
  '.json', '.xml', '.properties', '.sh', '.bash', '.zsh', '.tf',
];
const SKIP_EXTS = [
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico',
  '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
  '.exe', '.bin', '.dll', '.so', '.dylib',
  '.ttf', '.woff', '.woff2', '.eot',
  '.mp4', '.mp3', '.wav', '.avi',
  '.map',
];

function isScannableFile(filePath) {
  const lower = filePath.toLowerCase();
  if (SKIP_EXTS.some(e => lower.endsWith(e))) return false;
  if (lower.includes('.env')) return true;
  if (/node_modules|vendor\/|dist\/|build\//.test(filePath)) return false;
  return SCANNABLE_EXTS.some(e => lower.endsWith(e));
}

// ─── Shannon Entropy ──────────────────────────────────────────────────────────
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

// ─── Skip words ───────────────────────────────────────────────────────────────
const SKIP_WORDS = [
  'example','placeholder','your_','<your','xxx','test123','dummy','changeme',
  'replace','insert','todo','sample','fake','password123','xxxxxxxx','aaaaaaaa',
  '00000000','12345678','aaaaaa','abcdefgh','secret_here','key_here','mypassword',
  'mytoken','mykey','enter_here','put_here','change_me','fill_in','add_your',
  '<token>','<key>','<secret>','none','null','undefined','n/a',
];

function isSequential(str) {
  let asc = 0, desc = 0;
  for (let i = 1; i < str.length; i++) {
    if (str.charCodeAt(i) === str.charCodeAt(i - 1) + 1) asc++;
    if (str.charCodeAt(i) === str.charCodeAt(i - 1) - 1) desc++;
  }
  return Math.max(asc, desc) / str.length > 0.6;
}

function looksReal(val) {
  if (!val || val.length < 8) return false;
  const lower = val.toLowerCase();
  if (SKIP_WORDS.some(w => lower.includes(w))) return false;
  if (/^(.)\1+$/.test(val)) return false;
  if (/^[a-z\s]+$/.test(val)) return false;
  if (isSequential(val)) return false;
  const threshold = val.length > 40 ? 3.5 : val.length > 20 ? 3.8 : 4.0;
  return entropy(val) > threshold;
}

// ─── Comment line check ───────────────────────────────────────────────────────
function isCommentLine(line) {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('#') || t.startsWith('*') ||
         t.startsWith('/*') || t.startsWith('<!--') || t.startsWith('--');
}

// ─── Mask secret for safe display ────────────────────────────────────────────
function maskSecret(val) {
  if (!val || val.length <= 8) return '***';
  return val.substring(0, 4) + '****' + val.substring(val.length - 4);
}

// ─── Unique ID ────────────────────────────────────────────────────────────────
function uid() {
  return 'S-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8);
}

// ─── Rotation URLs ────────────────────────────────────────────────────────────
const ROTATION_URLS = {
  'AWS Access Key':        'https://console.aws.amazon.com/iam/home#/security_credentials',
  'AWS Secret Key':        'https://console.aws.amazon.com/iam/home#/security_credentials',
  'GCP Service Account':   'https://console.cloud.google.com/iam-admin/serviceaccounts',
  'Azure Client Secret':   'https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps',
  'GitHub Personal Token': 'https://github.com/settings/tokens',
  'GitHub OAuth Token':    'https://github.com/settings/tokens',
  'GitHub Actions Token':  'https://github.com/settings/tokens',
  'Stripe Secret Key':     'https://dashboard.stripe.com/apikeys',
  'Stripe Test Key':       'https://dashboard.stripe.com/test/apikeys',
  'Stripe Webhook Secret': 'https://dashboard.stripe.com/webhooks',
  'Google API Key':        'https://console.cloud.google.com/apis/credentials',
  'OpenAI API Key':        'https://platform.openai.com/api-keys',
  'Anthropic API Key':     'https://console.anthropic.com/settings/keys',
  'Groq API Key':          'https://console.groq.com/keys',
  'HuggingFace Token':     'https://huggingface.co/settings/tokens',
  'Slack Token':           'https://api.slack.com/apps',
  'Twilio Auth Token':     'https://console.twilio.com/us1/account/keys-credentials/api-keys',
  'Mailgun API Key':       'https://app.mailgun.com/settings/api_security',
  'SendGrid API Key':      'https://app.sendgrid.com/settings/api_keys',
  'Shopify Token':         'https://partners.shopify.com/organizations',
  'Okta API Token':        'https://your-domain.okta.com/admin/access/api/tokens',
  'Firebase Secret':       'https://console.firebase.google.com/project/_/settings/serviceaccounts',
  'MongoDB URI':           'https://cloud.mongodb.com — rotate DB password immediately',
  'PostgreSQL URI':        'Rotate DB password in your hosting provider dashboard',
  'MySQL URI':             'Rotate DB password in your hosting provider dashboard',
  'Redis URI':             'Rotate Redis password in your hosting provider dashboard',
  'RSA Private Key':       'Revoke and regenerate key pair immediately',
  'SSH Private Key':       'Remove from authorized_keys and generate new SSH key pair',
  'PGP Private Key':       'Revoke key from keyserver and generate new PGP key pair',
  'JWT Token':             'Invalidate by rotating JWT_SECRET in environment variables',
  'Generic API Key':       'Rotate in your service provider dashboard',
  'Hardcoded Password':    'Change immediately and store in environment variables',
  'Hardcoded Secret':      'Move to .env file and rotate the value',
};

// ─── Patterns (32 total) ──────────────────────────────────────────────────────
const PATTERNS = [
  // Cloud
  { name: 'AWS Access Key',        re: /AKIA[0-9A-Z]{16}/g,                                                      sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'AWS Secret Key',        re: /(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?/gi, sev: 'CRITICAL', cwe: 'CWE-798', capture: true },
  { name: 'GCP Service Account',   re: /"type"\s*:\s*"service_account"/g,                                         sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Azure Client Secret',   re: /(?:client[_-]?secret|AZURE[_-]?SECRET)\s*[=:]\s*["']([A-Za-z0-9~._\-]{30,})["']/gi, sev: 'CRITICAL', cwe: 'CWE-798', capture: true },

  // Source control
  { name: 'GitHub Personal Token', re: /ghp_[0-9a-zA-Z]{36}/g,                                                   sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'GitHub OAuth Token',    re: /gho_[0-9a-zA-Z]{36}/g,                                                   sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'GitHub Actions Token',  re: /ghs_[0-9a-zA-Z]{36}/g,                                                   sev: 'CRITICAL', cwe: 'CWE-798' },

  // Payment
  { name: 'Stripe Secret Key',     re: /sk_live_[0-9a-zA-Z]{24,}/g,                                              sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Stripe Test Key',       re: /sk_test_[0-9a-zA-Z]{24,}/g,                                              sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'Stripe Webhook Secret', re: /whsec_[0-9a-zA-Z]{32,}/g,                                                sev: 'HIGH',     cwe: 'CWE-798' },

  // AI APIs
  { name: 'OpenAI API Key',        re: /sk-[a-zA-Z0-9]{48}/g,                                                    sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Anthropic API Key',     re: /sk-ant-[a-zA-Z0-9\-_]{90,}/g,                                           sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Groq API Key',          re: /gsk_[a-zA-Z0-9]{50,}/g,                                                  sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'HuggingFace Token',     re: /hf_[a-zA-Z0-9]{30,}/g,                                                   sev: 'HIGH',     cwe: 'CWE-798' },

  // Other APIs
  { name: 'Google API Key',        re: /AIza[0-9A-Za-z\-_]{35}/g,                                               sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'Slack Token',           re: /xox[baprs]-[0-9A-Za-z\-]{10,}/g,                                        sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'Twilio Auth Token',     re: /(?:twilio[_-]?auth[_-]?token|TWILIO_TOKEN)\s*[=:]\s*["']([a-f0-9]{32})["']/gi, sev: 'HIGH', cwe: 'CWE-798', capture: true },
  { name: 'Mailgun API Key',       re: /key-[0-9a-zA-Z]{32}/g,                                                   sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'SendGrid API Key',      re: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g,                          sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'Shopify Token',         re: /shpat_[a-fA-F0-9]{32}/g,                                                 sev: 'HIGH',     cwe: 'CWE-798' },
  { name: 'Firebase Secret',       re: /AAAA[a-zA-Z0-9_\-]{100,}/g,                                             sev: 'HIGH',     cwe: 'CWE-798' },

  // Databases
  { name: 'MongoDB URI',           re: /mongodb(\+srv)?:\/\/[^\s"'`>]{10,}/g,                                    sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'PostgreSQL URI',        re: /postgres(ql)?:\/\/[^\s"'`>]{10,}/g,                                      sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'MySQL URI',             re: /mysql:\/\/[^\s"'`>]{10,}/g,                                              sev: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Redis URI',             re: /redis:\/\/[^\s"'`>]{10,}/g,                                              sev: 'HIGH',     cwe: 'CWE-798' },

  // Crypto keys
  { name: 'RSA Private Key',       re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g,                                sev: 'CRITICAL', cwe: 'CWE-321' },
  { name: 'SSH Private Key',       re: /-----BEGIN OPENSSH PRIVATE KEY-----/g,                                   sev: 'CRITICAL', cwe: 'CWE-321' },
  { name: 'PGP Private Key',       re: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,                                 sev: 'CRITICAL', cwe: 'CWE-321' },

  // JWT — strict 3-part pattern to avoid false positives
  { name: 'JWT Token',             re: /eyJ[A-Za-z0-9\-_]{20,}\.eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_.+/=]{20,}/g, sev: 'MEDIUM', cwe: 'CWE-522' },

  // Generic (entropy-gated)
  { name: 'Generic API Key',       re: /(?:api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi, sev: 'HIGH', cwe: 'CWE-798', capture: true },
  { name: 'Hardcoded Password',    re: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{8,})["']/gi,                 sev: 'HIGH',     cwe: 'CWE-259', capture: true },
  { name: 'Hardcoded Secret',      re: /(?:secret|token|private[_-]?key)\s*[=:]\s*["']([a-zA-Z0-9_\-]{16,})["']/gi, sev: 'HIGH',  cwe: 'CWE-798', capture: true },
];

// ─── Confidence scoring ───────────────────────────────────────────────────────
function getConfidence(pattern, value, ent) {
  if (!pattern.capture) return 'HIGH';
  if (ent > 4.0) return 'HIGH';
  if (ent > 3.5) return 'MEDIUM';
  return 'LOW';
}

// ─── File-level entropy heatmap ───────────────────────────────────────────────
function fileEntropyScore(content) {
  const tokens = content.match(/["'][A-Za-z0-9+/=_\-]{16,}["']/g) || [];
  if (!tokens.length) return 0;
  const total = tokens.reduce((sum, t) => sum + entropy(t.replace(/["']/g, '')), 0);
  return Math.round((total / tokens.length) * 100) / 100;
}

// ─── Main scan ────────────────────────────────────────────────────────────────
function scanSecrets(content, filePath) {
  if (!isScannableFile(filePath)) return [];

  const findings = [];
  const lines    = content.split('\n');
  const seen     = new Set();

  for (const p of PATTERNS) {
    try {
      const re = new RegExp(p.re.source, p.re.flags);
      let match;
      while ((match = re.exec(content)) !== null) {
        const matched = match[0];
        const value   = p.capture ? (match[1] || matched) : matched;

        if (p.capture && !looksReal(value)) continue;

        const lineNum  = content.substring(0, match.index).split('\n').length;
        const lineText = lineNum <= lines.length ? lines[lineNum - 1] : '';

        if (isCommentLine(lineText)) continue;

        const key = p.name + ':' + lineNum;
        if (seen.has(key)) continue;
        seen.add(key);

        const ent = entropy(value);

        findings.push({
          id:           uid(),
          type:         'SECRET',
          name:         p.name,
          severity:     p.sev,
          cwe:          p.cwe,
          owasp:        'A02:2021 - Cryptographic Failures',
          file:         filePath,
          line:         lineNum,
          lineText:     lineText.trim().substring(0, 120),
          matchPreview: maskSecret(matched),
          entropy:      ent,
          entropyRating: ent > 4.5 ? 'VERY HIGH' : ent > 3.8 ? 'HIGH' : ent > 3.2 ? 'MEDIUM' : 'LOW',
          confidence:   getConfidence(p, value, ent),
          description:  p.name + ' detected (entropy: ' + ent.toFixed(2) + '). Rotate immediately.',
          remediation:  'Move to environment variable. Use .env + dotenv. Never commit secrets to git.',
          rotationUrl:  ROTATION_URLS[p.name] || 'Rotate in your service provider dashboard.',
          mitre:        'T1552.001 - Credentials In Files',
        });
      }
    } catch (_) {}
  }

  return findings;
}

module.exports = { scanSecrets, entropy, fileEntropyScore, isScannableFile };
