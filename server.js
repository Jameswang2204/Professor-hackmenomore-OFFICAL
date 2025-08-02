// server.js
require('dotenv').config();                   // load .env
const express = require('express');
const cors    = require('cors');
const fetch   = require('node-fetch');        // npm install node-fetch@2
const { default: OpenAI } = require('openai'); // npm install openai

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));            // serve index.html, script.js, etc.

// === 1) Chat endpoint ===
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.post('/api/chat', async (req, res) => {
  try {
    const userMessage = req.body.message;
    if (!userMessage) {
      return res.status(400).json({ error: 'No message provided' });
    }

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: 'You are Professor Hackmenomore, a friendly cybersecurity tutor.' },
        { role: 'user',   content: userMessage }
      ],
      max_tokens: 500,
      temperature: 0.7,
    });

    return res.json({ reply: completion.choices[0].message.content });
  } catch (err) {
    console.error('OpenAI error:', err);
    return res.status(500).json({ error: 'OpenAI request failed' });
  }
});

// === 2) URLhaus-based malicious-link detection endpoint ===
app.post('/api/check-url', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'No URL provided' });
  }

  // Validate URL syntax
  try {
    const p = new URL(url);
    if (!['http:', 'https:'].includes(p.protocol)) {
      throw new Error('Invalid protocol');
    }
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  try {
    // Build form data per URLhaus spec
    const params = new URLSearchParams();
    params.append('url', url);

    // POST as application/x-www-form-urlencoded
    const phishRes = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    if (!phishRes.ok) {
      throw new Error(`URLhaus HTTP ${phishRes.status}`);
    }

    const data = await phishRes.json();  // now valid JSON
    // Interpret result
    // query_status 'no_results' → safe, url_status 'online' → malicious
    let verdict = 'unknown';
    if (data.query_status === 'no_results')   verdict = 'safe';
    else if (data.url_status === 'online')    verdict = 'malicious';

    return res.json({ verdict, details: data });
  } catch (err) {
    console.error('URLhaus error:', err);
    return res.status(502).json({ verdict: 'unknown', error: err.message });
  }
});  // end /api/check-url

// === 3) Start server ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});