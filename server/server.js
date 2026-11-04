const http = require('http');
const { analyzeUrl, defangUrl, refangUrl } = require('./analyzer');

const PORT = Number(process.env.PORT) || 10000;
// Sample demonstration URLs for fast 1-click testing
const DEMO_URLS = [
  {
    category: 'Safe & Verified',
    label: 'GitHub Official',
    url: 'https://github.com/security',
    expectedScore: '0-10'
  },
  {
    category: 'Brand Phishing / Typosquat',
    label: 'Spoofed PayPal Verification',
    url: 'http://paypa1-security-verification.xyz/login/verify-account',
    expectedScore: '80-100'
  },
  {
    category: 'Homograph Attack',
    label: 'Cyrillic Apple Impersonation',
    url: 'http://аррӏе.com/security/login',
    expectedScore: '75-100'
  },
  {
    category: 'Malware Host',
    label: 'Raw IP with Login Script',
    url: 'http://192.168.1.105:8080/admin/login.php',
    expectedScore: '60-85'
  },
  {
    category: 'Suspicious Subdomain Depth',
    label: 'Deep Obfuscation Subdomains',
    url: 'http://secure.account.update.verify.bankofamerica.support-cloud.xyz',
    expectedScore: '75-100'
  }
];

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function sendJson(res, statusCode, data) {
  setCorsHeaders(res);
  res.setHeader('Content-Type', 'application/json');
  res.writeHead(statusCode);
  res.end(JSON.stringify(data));
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 1e6) { // 1MB limit
        reject(new Error('Request payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(new Error('Invalid JSON format'));
      }
    });
    req.on('error', err => reject(err));
  });
}

const server = http.createServer(async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    setCorsHeaders(res);
    res.writeHead(204);
    return res.end();
  }

  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = reqUrl.pathname;

  try {
    // Health Check
    if (req.method === 'GET' && pathname === '/api/health') {
      return sendJson(res, 200, {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'AegisGuard URL Risk Detector API v1.0',
        uptime: process.uptime()
      });
    }

    // Sample URLs
    if (req.method === 'GET' && pathname === '/api/sample-urls') {
      return sendJson(res, 200, DEMO_URLS);
    }

    // Single URL scan endpoint
    if (req.method === 'POST' && pathname === '/api/scan') {
      const body = await parseJsonBody(req);
      const { url } = body;
      if (!url || typeof url !== 'string' || !url.trim()) {
        return sendJson(res, 400, { error: 'Please provide a valid URL string.' });
      }

      const result = await analyzeUrl(url.trim());
      return sendJson(res, 200, result);
    }

    // Batch URL scan endpoint
    if (req.method === 'POST' && pathname === '/api/batch-scan') {
      const body = await parseJsonBody(req);
      const { urls } = body;
      if (!Array.isArray(urls) || urls.length === 0) {
        return sendJson(res, 400, { error: 'Please provide an array of URLs.' });
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

      return sendJson(res, 200, {
        summary: {
          total,
          safeCount,
          suspiciousCount,
          maliciousCount,
          avgScore
        },
        results
      });
    }

    // Defang / Refang endpoint
    if (req.method === 'POST' && pathname === '/api/defang') {
      const body = await parseJsonBody(req);
      const { url, action } = body;
      if (!url || typeof url !== 'string') {
        return sendJson(res, 400, { error: 'URL is required' });
      }

      if (action === 'refang') {
        return sendJson(res, 200, { result: refangUrl(url) });
      }
      return sendJson(res, 200, { result: defangUrl(url) });
    }

    // Serve static files from client/dist if available
    const fs = require('fs');
    const path = require('path');
    const clientDistPath = path.resolve(__dirname, '../client/dist');

    if (fs.existsSync(clientDistPath)) {
      let filePath = path.join(clientDistPath, pathname === '/' ? 'index.html' : pathname);
      
      // If file doesn't exist directly, fallback to index.html for client-side routing
      if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        filePath = path.join(clientDistPath, 'index.html');
      }

      if (fs.existsSync(filePath)) {
        const ext = path.extname(filePath).toLowerCase();
        const mimeTypes = {
          '.html': 'text/html',
          '.js': 'application/javascript',
          '.css': 'text/css',
          '.json': 'application/json',
          '.svg': 'image/svg+xml',
          '.png': 'image/png',
          '.jpg': 'image/jpeg',
          '.ico': 'image/x-icon',
          '.woff': 'font/woff',
          '.woff2': 'font/woff2'
        };

        const contentType = mimeTypes[ext] || 'application/octet-stream';
        setCorsHeaders(res);
        res.setHeader('Content-Type', contentType);
        res.writeHead(200);
        fs.createReadStream(filePath).pipe(res);
        return;
      }
    }

    // 404 Fallback
    return sendJson(res, 404, { error: 'Route not found' });
  } catch (err) {
    return sendJson(res, 500, { error: err.message || 'Internal server error' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[URL-RISK-DETECTOR API] Running on 0.0.0.0:${PORT}`);
});
