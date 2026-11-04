const { analyzeUrl } = require('./analyzer');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed. Use POST.' });
  }

  try {
    let body = req.body;
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch (e) {
        // keep as is
      }
    }

    const { urls } = body || {};
    if (!Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({ error: 'Please provide an array of URLs.' });
    }

    const targetUrls = urls.slice(0, 30);
    const results = [];

    for (const u of targetUrls) {
      if (!u || typeof u !== 'string' || !u.trim()) continue;
      try {
        const item = await analyzeUrl(u.trim());
        results.push(item);
      } catch (e) {
        results.push({
          url: u,
          error: e.message || 'Analysis error',
          riskScore: 50,
          riskLevel: 'Error'
        });
      }
    }

    const total = results.length;
    const safeCount = results.filter(r => r.riskLevel === 'Safe' || r.riskLevel === 'Low Risk').length;
    const suspiciousCount = results.filter(r => r.riskLevel === 'Suspicious').length;
    const maliciousCount = results.filter(r => r.riskLevel === 'Malicious').length;
    const avgScore = total > 0 ? Math.round(results.reduce((acc, cur) => acc + (cur.riskScore || 0), 0) / total) : 0;

    return res.status(200).json({
      summary: {
        total,
        safeCount,
        suspiciousCount,
        maliciousCount,
        avgScore
      },
      results
    });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Batch scan failed' });
  }
};
