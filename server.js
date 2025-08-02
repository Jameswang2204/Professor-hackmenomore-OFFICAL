// Updated server.js with better error handling and debugging
require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const fetch   = require('node-fetch');        // npm install node-fetch@2
const { default: OpenAI } = require('openai'); // npm install openai

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// === OpenAI Chat endpoint ===
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

// === Improved URL Checker endpoint ===
app.post('/api/check-url', async (req, res) => {
  console.log('URL check request received:', req.body);
  
  const { url } = req.body;
  if (!url) {
    console.log('No URL provided');
    return res.status(400).json({ error: 'No URL provided' });
  }

  // Validate URL syntax
  try {
    const parsedUrl = new URL(url);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      throw new Error('Invalid protocol');
    }
    console.log('URL validation passed:', url);
  } catch (error) {
    console.log('URL validation failed:', error.message);
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  try {
    console.log('Checking URL with URLhaus API...');
    
    // Build form data for URLhaus API
    const params = new URLSearchParams();
    params.append('url', url);

    // Make request to URLhaus API
    const apiResponse = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Professor Hackmenomore URL Checker'
      },
      body: params.toString(),
      timeout: 10000 // 10 second timeout
    });

    console.log('URLhaus API response status:', apiResponse.status);

    if (!apiResponse.ok) {
      throw new Error(`URLhaus API returned ${apiResponse.status}`);
    }

    const responseText = await apiResponse.text();
    console.log('URLhaus API raw response:', responseText);

    let data;
    try {
      data = JSON.parse(responseText);
    } catch (parseError) {
      console.error('Failed to parse URLhaus response as JSON:', parseError);
      throw new Error('Invalid JSON response from URLhaus API');
    }

    console.log('URLhaus API parsed data:', data);

    // Determine verdict based on URLhaus response
    let verdict = 'unknown';
    let explanation = '';

    if (data.query_status === 'no_results') {
      verdict = 'safe';
      explanation = 'URL not found in URLhaus malware database';
    } else if (data.query_status === 'ok') {
      if (data.url_status === 'online') {
        verdict = 'malicious';
        explanation = 'URL is active and flagged as malicious';
      } else if (data.url_status === 'offline') {
        verdict = 'suspicious';
        explanation = 'URL was previously flagged but is now offline';
      } else {
        verdict = 'unknown';
        explanation = `URL status: ${data.url_status}`;
      }
    } else {
      verdict = 'unknown';
      explanation = `Query status: ${data.query_status}`;
    }

    console.log('Final verdict:', verdict, explanation);

    return res.json({ 
      verdict, 
      explanation,
      details: data 
    });

  } catch (error) {
    console.error('URL check error:', error);
    
    // Fallback to simple domain-based checks if URLhaus fails
    try {
      const domain = new URL(url).hostname.toLowerCase();
      
      // Simple heuristic checks
      const suspiciousPatterns = [
        /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // IP addresses
        /[a-z0-9\-]{20,}\./, // Very long subdomains
        /bit\.ly|tinyurl|t\.co/, // URL shorteners (could be suspicious)
        /[0-9]+[a-z]+[0-9]+/, // Mixed numbers and letters in domain
      ];

      const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(domain));
      
      return res.json({ 
        verdict: isSuspicious ? 'suspicious' : 'unknown',
        explanation: isSuspicious ? 
          'URL has suspicious characteristics (fallback check)' : 
          'Could not verify URL safety (external API unavailable)',
        error: error.message,
        fallback: true
      });
    } catch (fallbackError) {
      console.error('Fallback check also failed:', fallbackError);
      return res.status(500).json({ 
        verdict: 'unknown', 
        error: 'URL check service temporarily unavailable',
        details: error.message 
      });
    }
  }
});

// === Start server ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
  console.log('URL Checker endpoint available at /api/check-url');
});