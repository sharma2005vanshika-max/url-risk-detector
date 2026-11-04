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

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  return res.status(200).json(DEMO_URLS);
};
