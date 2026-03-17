'use strict';
const express  = require('express');
const router   = express.Router();
const { parseUrl, createPR } = require('../services/githubService');

// POST /api/github/create-pr
router.post('/create-pr', async (req, res) => {
  const { repo_url, github_token, finding, fixedCode, filePath } = req.body;
  if (!repo_url || !github_token || !finding || !fixedCode || !filePath)
    return res.status(400).json({ error: 'repo_url, github_token, finding, fixedCode, filePath are all required' });

  let owner, repo;
  try { ({ owner, repo } = parseUrl(repo_url)); }
  catch (e) { return res.status(400).json({ error: e.message }); }

  try {
    const result = await createPR({ owner, repo, token: github_token, filePath, fixedContent: fixedCode, finding });
    return res.json(result);
  } catch (e) {
    return res.status(500).json({ error: 'PR creation failed: ' + e.message });
  }
});

module.exports = router;
