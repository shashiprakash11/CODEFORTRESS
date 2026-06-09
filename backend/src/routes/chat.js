'use strict';
const express = require('express');
const router  = express.Router();
const axios   = require('axios');

router.post('/', async (req, res) => {
  const { message, context } = req.body;
  if (!message) return res.status(400).json({ error: 'message required' });
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'AI unavailable.' });
  try {
    const { data } = await axios.post(
      'https://api.groq.com/openai/v1/chat/completions',
      { model: 'llama-3.3-70b-versatile', max_tokens: 500, temperature: 0.3,
        messages: [
          { role: 'system', content: `You are CodeFortress CI Security Assistant. Be concise and technical. ${context||''}` },
          { role: 'user', content: message }
        ]},
      { headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' }, timeout: 20000 }
    );
    return res.json({ answer: data.choices?.[0]?.message?.content?.trim() });
  } catch(err) {
    console.error('[chat]', err.message);
    return res.status(500).json({ error: 'AI unavailable. Try again.' });
  }
});
module.exports = router;
