'use strict';
const express  = require('express');
const router   = express.Router();
const { generateFix } = require('../services/autoFix');

// POST /api/fix
router.post('/', async (req, res) => {
  const { finding, fileContent } = req.body;
  if (!finding) return res.status(400).json({ error: 'finding is required' });
  try {
    const result = await generateFix(finding, fileContent || '');
    return res.json({ ...result, finding, timestamp: new Date().toISOString() });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

module.exports = router;
