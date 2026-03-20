# 🛡️ CodeFortress CI ----- https://codefortress.vercel.app/

<div align="center">

**Autonomous Security Platform for GitHub Repositories**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel-black?style=for-the-badge&logo=vercel)](https://codefortress-security-platform.vercel.app)
[![Backend](https://img.shields.io/badge/Backend-Render-46E3B7?style=for-the-badge&logo=render)](https://codefortress-backend.onrender.com/api/health)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Node](https://img.shields.io/badge/Node.js-18+-green?style=for-the-badge&logo=node.js)](https://nodejs.org)


</div>

---

## 🎬 What It Does

CodeFortress CI scans any public GitHub repository for real security vulnerabilities — hardcoded secrets, SQL injection, XSS, command injection, and more. It then uses **Groq Llama AI** to generate secure code patches instantly.

```
GitHub Repo URL → Real File Download → Security Scan → AI Fix → Secure Code
```

---

## Features 

| Feature | How It Works |
|---------|-------------|
| **Secret Detection** | 13 regex patterns + Shannon Entropy algorithm on real files |
| **SAST Analysis** | 10 OWASP rules — SQL Injection, XSS, CMDi, Path Traversal, etc. |
| **GitHub Integration** | Downloads actual files via GitHub REST API v3 |
| **AI Auto-Fix** | Groq Llama-3.3-70b generates secure code patches |
| **Risk Scoring** | CRITICAL=10, HIGH=5, MEDIUM=2 — weighted calculation |
| **Attack Paths** | Rule-based CWE/MITRE ATT&CK mapping from real findings |
| **3D Visualization** | Three.js WebGL — Security Memory Graph |
| **Real-time Logs** | Live scan progress per ML layer |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND (Vercel)                     │
│  HTML5 + CSS3 + Vanilla JS + Three.js + Canvas API      │
│  8-Layer ML Animation · Toast · Donut Chart · Gauge     │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTPS API calls
┌──────────────────────▼──────────────────────────────────┐
│                    BACKEND (Render)                      │
│  Node.js 18 + Express · CORS · Helmet · Rate Limiting   │
├─────────────────────────────────────────────────────────┤
│  /api/scan    → GitHub API → File Download → Scan       │
│  /api/fix     → Groq Llama-3.3-70b → Secure Patch      │
│  /api/health  → Status Check                            │
└──────────────┬─────────────────────┬────────────────────┘
               │                     │
    ┌──────────▼──────┐   ┌──────────▼──────────┐
    │   GitHub API    │   │    Groq API          │
    │  File Download  │   │  Llama-3.3-70b       │
    └─────────────────┘   └─────────────────────┘
```

---

## 🔍 Security Scanning Details

### Secret Detection (13 patterns + Shannon Entropy)
```
AWS Access Keys    → AKIA[0-9A-Z]{16}
GitHub Tokens      → ghp_[0-9a-zA-Z]{36}
Stripe Live Keys   → sk_live_[0-9a-zA-Z]{24,}
Google API Keys    → AIza[0-9A-Za-z\-_]{35}
Slack Tokens       → xoxb-[0-9A-Za-z\-]{50,}
MongoDB URIs       → mongodb+srv://...
Private Keys       → -----BEGIN RSA PRIVATE KEY-----
+ 6 more patterns
+ Shannon Entropy > 3.2 threshold
```

### SAST Rules (10 OWASP patterns)
```
CWE-89   SQL Injection           → String concat in queries
CWE-78   Command Injection       → exec() with user input
CWE-79   Cross-Site Scripting    → innerHTML = user input
CWE-22   Path Traversal          → readFile with params
CWE-327  Weak Cryptography       → MD5/SHA1 usage
CWE-215  Debug Mode              → debug: true
CWE-502  Insecure Eval           → eval(user input)
CWE-601  Unvalidated Redirect    → res.redirect(req.query)
CWE-1321 Prototype Pollution     → Object.assign(__proto__)
CWE-918  SSRF                    → fetch(user controlled URL)
```

---

## 📁 Project Structure

```
CODEFORTRESS/
├── frontend/
│   └── index.html              ← Complete frontend (single file)
│                                  Three.js 3D · 8-layer animation
│                                  Groq AI chatbot · Toast notifications
│                                  Donut chart · Risk gauge · Export PDF
│
├── backend/
│   ├── src/
│   │   ├── index.js            ← Express server + keep-alive
│   │   ├── routes/
│   │   │   ├── scan.js         ← POST /api/scan
│   │   │   ├── fix.js          ← POST /api/fix
│   │   │   └── github.js       ← POST /api/github/create-pr
│   │   └── services/
│   │       ├── secretScanner.js   ← 13 patterns + entropy
│   │       ├── sastScanner.js     ← 10 OWASP rules
│   │       ├── githubService.js   ← GitHub REST API v3
│   │       └── autoFix.js         ← Groq AI integration
│   ├── package.json
│   ├── Procfile                ← Render deploy
│   └── .env.example
│
├── vercel.json                 ← Frontend deploy config
└── README.md
```

---

## 🚀 Local Setup

### Prerequisites
- Node.js 18+ → [nodejs.org](https://nodejs.org)
- Git

### 1. Clone
```bash
git clone https://github.com/shashiprakash11/CODEFORTRESS.git
cd CODEFORTRESS
```

### 2. Backend Setup
```bash
cd backend
npm install
cp .env.example .env
```

Edit `.env`:
```env
GROQ_API_KEY=gsk_xxxx        # console.groq.com — Free
GITHUB_TOKEN=ghp_xxxx        # github.com/settings/tokens — Optional
NODE_ENV=development
PORT=4000
```

### 3. Start Backend
```bash
npm run dev
# Running at http://localhost:4000
# Test: http://localhost:4000/api/health
```

### 4. Open Frontend
```bash
# Open in browser
open frontend/index.html
# Or use VS Code Live Server
```

Set Backend URL in app topbar: `http://localhost:4000`

---

## ☁️ Deployment

| Service | Platform | URL |
|---------|----------|-----|
| Frontend | Vercel (Free) | [codefortress-security-platform.vercel.app](https://codefortress-security-platform.vercel.app) |
| Backend | Render (Free) | [codefortress-backend.onrender.com](https://codefortress-backend.onrender.com/api/health) |
| Uptime Monitor | UptimeRobot (Free) | Pings every 5 min |

### Deploy Frontend (Vercel)
1. Push to GitHub
2. Import repo at [vercel.com](https://vercel.com)
3. Root Directory: `frontend`
4. Deploy → Live in 60 seconds

### Deploy Backend (Render)
1. New Web Service at [render.com](https://render.com)
2. Root Directory: `backend`
3. Start Command: `node src/index.js`
4. Add env vars: `GROQ_API_KEY`, `GITHUB_TOKEN`
5. Deploy → Free tier, always on with UptimeRobot

---

## 🧪 Test It

### Scan a vulnerable demo repo:
```
https://github.com/shashiprakash11/vulnerablerepo
```

**Expected findings:**
- 4+ hardcoded secrets (Stripe, AWS, GitHub token, password)
- 6+ SAST vulnerabilities (SQL injection, XSS, command injection...)
- Risk Score: 70+ / FAILED
- Try your own repo for more accurate understandings.

### API Test:
```bash
# Health check
curl https://codefortress-backend.onrender.com/api/health

# Scan a repo
curl -X POST https://codefortress-backend.onrender.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/shashiprakash11/hackverse-demo-app"}'
```

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| 3D Graphics | Three.js r128 (WebGL) |
| AI / Fix Generation | Groq API — Llama-3.3-70b-versatile |
| Security Algorithms | Shannon Entropy, Regex Pattern Matching |
| Security Standards | OWASP Top 10, CWE Taxonomy, MITRE ATT&CK |
| Backend | Node.js 18, Express.js |
| GitHub Integration | GitHub REST API v3 |
| Frontend Deploy | Vercel |
| Backend Deploy | Render |
| Uptime Monitoring | UptimeRobot |

---

## 📊 8-Layer ML Pipeline

The scanning process runs through 8 visual stages:

| Layer | Name | What It Does |
|-------|------|-------------|
| 1 | Secret Prediction | Shannon entropy + 13 regex patterns on real files |
| 2 | Contextual SAST | 10 OWASP vulnerability rules on actual code |
| 3 | Attack Path GNN | Rule-based CWE/MITRE attack path generation |
| 4 | DAST Runtime | Animation layer (static scanner — no runtime app needed) |
| 5 | Security Memory | Repo metadata + scan context visualization |
| 6 | Decision Intelligence | Weighted risk scoring algorithm |
| 7 | XAI Attribution | Animation layer |
| 8 | Patch Synthesis | **Real** — Groq Llama AI generates secure patches |

---

## 📸 Screenshots

> Intelligence Space · Attack Simulator · Security Memory · Risk Maps · Policy Center

*Run a scan on the live demo to see real results.*

---

## 👨‍💻 Author

**SHASHI PRAKASH**

---

## 📄 License

MIT License — Free to use and modify.
