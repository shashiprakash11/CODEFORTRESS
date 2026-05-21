'use strict';
const express = require('express');
const router  = express.Router();

// GET /api/badge?owner=xx&repo=yy&score=85&grade=F
router.get('/', (req, res) => {
  const { owner, repo, score, grade, label } = req.query;
  if (!grade) return res.status(400).send('grade required');

  const COLOR = {
    'A': '#22c55e', 'B': '#84cc16',
    'C': '#f59e0b', 'D': '#f97316',
    'F': '#ef4444',
  };
  const color = COLOR[grade] || '#6b7280';
  const text  = label || `Grade ${grade} · ${score || '?'}/100`;
  const width = 180;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-cache, max-age=0');
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="${width}" height="20" fill="#555"/>
  <rect rx="3" x="90" width="90" height="20" fill="${color}"/>
  <rect rx="3" width="${width}" height="20" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="11">
    <text x="45" y="14" fill="#fff" opacity=".8">CodeFortress</text>
    <text x="135" y="14">${text}</text>
  </g>
</svg>`);
});

module.exports = router;
