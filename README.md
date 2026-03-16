# 🛡️ CodeFortress CI
### Autonomous Risk-Adaptive Secure CI/CD Platform

> Final Year Project | CS/IT | React + Node.js | Real Security Scanning | AI Auto-Fix

---

## 📁 Project Structure

```
CODEFORTRESS/
│
├── frontend/
│   └── index.html          ← Poora frontend (single HTML file)
│                             Three.js 3D, Claude chatbot, 8-layer animation
│
├── backend/
│   ├── src/
│   │   ├── index.js                    ← Express server
│   │   ├── routes/
│   │   │   ├── scan.js                 ← /api/scan
│   │   │   ├── fix.js                  ← /api/fix
│   │   │   └── github.js               ← /api/github/create-pr
│   │   └── services/
│   │       ├── secretScanner.js        ← 16 secret patterns + entropy
│   │       ├── sastScanner.js          ← 10 OWASP vulnerability rules
│   │       ├── githubService.js        ← GitHub REST API
│   │       └── autoFix.js              ← Claude AI auto-fix
│   ├── package.json
│   ├── Procfile                        ← Railway/Render deploy
│   └── .env.example                   ← Copy to .env
│
├── vercel.json             ← Frontend deploy config
├── package.json            ← Root scripts
└── README.md               ← This file
```

---

## 🚀 STEP 1 — Local pe chalao (5 minutes)

### Prerequisites
- Node.js 18+ installed (nodejs.org se download karo)
- Any browser (Chrome/Firefox)

### Frontend only (No backend needed)
```bash
# index.html ko directly browser mein open karo
# Double click on: CODEFORTRESS/frontend/index.html
```
Ya VS Code mein "Live Server" extension use karo.

### Frontend + Backend (Full real scanning)
```bash
# Terminal 1 — Backend
cd CODEFORTRESS/backend
npm install
cp .env.example .env
# .env file mein API keys daalo (instructions neeche)
npm run dev
# Backend chalu ho jaayega at: http://localhost:4000

# Terminal 2 — Frontend
# browser mein kholo: CODEFORTRESS/frontend/index.html
```

Test karo:
1. Browser mein `index.html` open karo
2. GitHub URL daalo: `https://github.com/Harshvardhansinh28/HACKVERSE`
3. "Initialize Secure Audit" click karo
4. 8-layer animation dekhoge + real findings!

---

## ☁️ STEP 2 — Frontend Vercel pe deploy karo (FREE)

### Option A — Easiest (Drag & Drop, 5 minutes)
1. **vercel.com** pe jaao
2. GitHub se sign up karo (free)
3. Dashboard pe **"Add New Project"** click karo
4. **"Deploy without a Git repository"** select karo
5. Poora **CODEFORTRESS folder** drag & drop karo
6. **Deploy** click karo
7. 60 seconds mein live URL milega! ✅
   Example: `https://codefortress-xyz.vercel.app`

### Option B — GitHub Integration (Best for updates)
```bash
# Step 1: GitHub pe naya repo banao
# github.com → New Repository → "CODEFORTRESS"

# Step 2: Poora project push karo
cd CODEFORTRESS
git init
git add .
git commit -m "Initial commit — CodeFortress CI"
git remote add origin https://github.com/YOUR_USERNAME/CODEFORTRESS.git
git push -u origin main

# Step 3: Vercel pe import karo
# vercel.com → Add New Project → Import from GitHub
# CODEFORTRESS repo select karo → Deploy!
```
Ab jab bhi code change karo aur GitHub pe push karo → Vercel automatically redeploy karega.

---

## ☁️ STEP 3 — Backend Railway pe deploy karo (FREE)

1. **railway.app** pe jaao → GitHub se sign up karo
2. **"New Project"** → **"Deploy from GitHub repo"**
3. **CODEFORTRESS** repo select karo
4. **"Add Service"** → Select **backend** folder
5. **Environment Variables** add karo:
   ```
   ANTHROPIC_API_KEY = your_key
   GITHUB_TOKEN = your_token
   NODE_ENV = production
   ```
6. Deploy click karo → Railway URL milega
   Example: `https://codefortress-backend.up.railway.app`

7. **Frontend mein backend URL daalo:**
   `index.html` mein topbar ka input field mein apna Railway URL paste karo.

---

## 🔑 STEP 4 — API Keys setup karo

### Anthropic API Key (Claude AI auto-fix ke liye)
1. **console.anthropic.com** pe jaao
2. Free account banao → **$5 free credits** milte hain signup pe
3. **"API Keys"** → **"Create Key"** → Copy karo
4. App ke topbar input mein paste karo: `Anthropic API Key (optional)`
5. Ab "⚡ Fix" button real Claude-generated secure code dega!

### GitHub Token (Private repos + PR creation ke liye)
1. **github.com/settings/tokens** pe jaao
2. **"Generate new token (classic)"**
3. Name: `CodeFortress CI`
4. Scope check karo: ✅ **repo** (full control)
5. Generate → Copy karo (ek baar hi dikhta hai!)
6. `.env` file mein daalo: `GITHUB_TOKEN=your_token`

---

## 🎓 STEP 5 — Final Year Presentation ke liye

### Live Demo Script (7 minutes)
```
1. App open karo — dark theme, professional UI dikhao (30 sec)
2. GitHub URL paste karo → Scan initialize karo (30 sec)
3. 8-layer ML animation dikhao — explain each layer (2 min)
4. Real findings dikhao — file names + line numbers (1.5 min)
5. "⚡ Fix" click karo → Claude AI ka secure code patch dikhao (1 min)
6. Attack Simulator — CWE/MITRE ATT&CK mapping explain karo (1 min)
7. Three.js Security Memory page — 3D visualization dikhao (30 sec)
```

### Examiner Questions ke Answers

**Q: "Ye actual scanning karta hai ya simulated?"**
A: "Haan sir, GitHub API se real files download karta hai, Shannon entropy
   algorithm se secrets detect karta hai, aur 10 OWASP pattern rules se
   SQL injection, XSS, command injection real code mein dhundta hai."

**Q: "ML model kahan hai? Kaise train kiya?"**
A: "8-layer pipeline ka visual representation hai. Secret prediction Shannon
   entropy aur 16 regex patterns use karta hai — same approach jo TruffleHog
   jaise industry tools use karte hain. Full GNN training ke liye CVE labeled
   dataset aur months of compute chahiye — jo production companies use karti hain."

**Q: "AI integration kaise kaam karta hai?"**
A: "Anthropic Claude claude-sonnet-4 API directly call hoti hai. Finding ka code
   context bhejta hoon, Claude context-aware secure fix generate karta hai.
   Real API call hai — simulated nahi."

**Q: "Real world mein kaise use hoga?"**
A: "CI/CD pipeline mein integrate kar sakte hain — GitHub Actions ke saath.
   Har push pe automatically scan ho, vulnerabilities block ho, aur auto-fix PR
   create ho — bina developer ke kuch kiye."

---

## 🛠️ Tech Stack (Resume ke liye)

| Category | Technology |
|----------|-----------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| 3D Graphics | Three.js (WebGL renderer) |
| AI/ML | Anthropic Claude claude-sonnet-4 API |
| Security | OWASP Top 10, CWE taxonomy, MITRE ATT&CK |
| Algorithms | Shannon Entropy, Regex pattern matching, Weighted risk scoring |
| APIs | GitHub REST API v3, Anthropic Messages API |
| Backend | Node.js 18, Express.js |
| Deployment | Vercel (frontend), Railway (backend) |
| Design | Custom dark theme, CSS animations, Three.js WebGL |

---

## ⚡ Quick Reference

| Action | Command |
|--------|---------|
| Backend start | `cd backend && npm run dev` |
| Backend test | `curl http://localhost:4000/api/health` |
| Scan test | `curl -X POST http://localhost:4000/api/scan -H "Content-Type: application/json" -d '{"repo_url":"https://github.com/Harshvardhansinh28/HACKVERSE"}'` |
| Git push | `git add . && git commit -m "update" && git push` |
