'use strict';
const express  = require('express');
const router   = express.Router();
const { parseUrl, getMeta, getFiles, fetchContent } = require('../services/githubService');
const { scanSecrets, fileEntropyScore } = require('../services/secretScanner');
const { scanSAST, riskScore, attackPaths } = require('../services/sastScanner');

// POST /api/scan
router.post('/', async (req, res) => {
  const { repo_url, github_token } = req.body;
  if (!repo_url) return res.status(400).json({ error: 'repo_url is required' });

  let owner, repo;
  try { ({ owner, repo } = parseUrl(repo_url)); }
  catch (e) { return res.status(400).json({ error: e.message }); }

  const token = github_token || process.env.GITHUB_TOKEN || '';

  try {
    // 1. Metadata
    const meta = await getMeta(owner, repo, token);

    // 2. File list
    const files = await getFiles(owner, repo, token, '', 0);
    if (!files.length) return res.status(404).json({
      error: 'No scannable files found.',
      hint: 'Ensure repo is public or provide a GitHub token.'
    });

    // 3. Scan files in batches of 10
    const allFindings  = [];
    const scanned      = [];
    const fileEntropies = [];
    const BATCH       = 10;
    const cap         = Math.min(files.length, 80);

    for (let i = 0; i < cap; i += BATCH) {
      const batch = files.slice(i, i + BATCH);
      const results = await Promise.allSettled(
        batch.map(async f => {
          const content = await fetchContent(f.url, token);
          if (!content) return [];
          scanned.push(f.path);
              fileEntropies.push(fileEntropyScore(content));
              return [...scanSecrets(content, f.path), ...scanSAST(content, f.path)];
        })
      );
      results.forEach(r => {
        if (r.status === 'fulfilled' && r.value) allFindings.push(...r.value);
      });
    }

// 4. Deduplicate findings — same rule same line same file = one finding
    const seen    = new Set();
    const deduped = allFindings.filter(f => {
      const key = f.name + ':' + f.file + ':' + f.line;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // 5. Risk score
    const risk = riskScore(deduped);
    // 5. Attack paths
    const paths = attackPaths(allFindings, repo);

   // 6. Real cluster entropy — average Shannon entropy across all scanned files
    const clusterEntropy = fileEntropies.length
      ? parseFloat((fileEntropies.reduce((a, b) => a + b, 0) / fileEntropies.length).toFixed(3))
      : 0;
    );

    return res.json({
      repo: {
        owner, name: repo,
        fullName:    meta.full_name,
        description: meta.description || '',
        language:    meta.language || 'Unknown',
        stars:       meta.stargazers_count || 0,
        forks:       meta.forks_count || 0,
        avatarUrl:   meta.owner?.avatar_url || '',
        isPrivate:   meta.private || false,
        defaultBranch: meta.default_branch || 'main',
        topics:      meta.topics || []
      },
      scan: {
        filesScanned:  scanned.length,
        totalFiles:    files.length,
        secretsFound:  allFindings.filter(f => f.type === 'SECRET').length,
        sastFound:     allFindings.filter(f => f.type === 'SAST').length,
        scannedAt:     new Date().toISOString()
      },
      risk,
      clusterEntropy,
      findings:    allFindings,
      attackPaths: paths
    });

  } catch (err) {
    console.error('Scan error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/scan/stream — Server-Sent Events for progress
router.get('/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const stages = [
    { index: 0, label: 'Connecting to GitHub API...',              progress: 8   },
    { index: 1, label: 'Fetching repository file tree...',          progress: 18  },
  { index: 2, label: 'Analyzing repository file structure...',         progress: 28  },
{ index: 3, label: '[SECRET_SCAN] Running entropy + pattern analysis...', progress: 38  },
{ index: 4, label: '[SAST_SCAN] Checking OWASP Top 10 rules...',    progress: 50  },
{ index: 5, label: '[ATTACK_MAP] Mapping CWE/MITRE attack paths...', progress: 62  },
{ index: 6, label: '[RISK_ENGINE] Computing weighted severity score...', progress: 72  },
{ index: 7, label: '[PATTERN_DB] Cross-referencing CVE database...', progress: 82  },
{ index: 8, label: '[VERDICT] Synthesizing final risk verdict...',   progress: 90  },
{ index: 9, label: '[AI_ENGINE] Preparing Groq fix engine...',       progress: 96  },
{ index:10, label: '[REPORT] Generating findings report...',         progress: 99  },
    { index:11, label: 'Consolidating results...',                   progress: 100, done: true }
  ];

  let i = 0;
  const iv = setInterval(() => {
    if (i >= stages.length) { clearInterval(iv); res.end(); return; }
    res.write('data: ' + JSON.stringify(stages[i]) + '\n\n');
    i++;
  }, 400);

  req.on('close', () => clearInterval(iv));
});

module.exports = router;
