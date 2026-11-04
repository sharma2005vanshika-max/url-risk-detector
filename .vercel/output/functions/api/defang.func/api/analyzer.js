const dns = require('dns').promises;
const tls = require('tls');
const url = require('url');

// Curated Top 50 Global Trusted Domains (Exact match or true subdomain)
const TOP_TRUSTED_DOMAINS = new Set([
  'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
  'github.com', 'wikipedia.org', 'cloudflare.com', 'netflix.com', 'yahoo.com',
  'reddit.com', 'bing.com', 'live.com', 'office.com', 'openai.com',
  'zoom.us', 'whatsapp.com', 'tiktok.com', 'pinterest.com', 'adobe.com',
  'spotify.com', 'dropbox.com', 'salesforce.com', 'twitch.tv', 'medium.com',
  'quora.com', 'ebay.com', 'craigslist.org', 'walmart.com', 'paypal.com',
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'cnn.com', 'bbc.com',
  'nytimes.com', 'theguardian.com', 'stackoverflow.com', 'gitlab.com', 'npm.js',
  'npmjs.com', 'mozilla.org', 'w3schools.com', 'archive.org', 'bitbucket.org'
]);

// High-Risk / Commonly Abused TLDs
const HIGH_RISK_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click',
  'country', 'buzz', 'icu', 'cam', 'rest', 'bid', 'surf', 'loan', 'bar',
  'stream', 'party', 'trade', 'racing', 'accountant', 'date', 'faith', 'review'
]);

// Known Brand Targets for Typosquatting / Impersonation Detection
const TARGET_BRANDS = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook',
  'instagram', 'whatsapp', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
  'binance', 'coinbase', 'metamask', 'steam', 'roblox', 'telegram', 'twitter',
  'spotify', 'linkedin', 'dropbox', 'github', 'discord', 'adobe', 'walmart'
];

// Phishing / Suspicious Action Keywords
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'update', 'banking', 'secure',
  'account', 'security', 'wallet', 'password', 'credential', 'auth', 'recover',
  'suspension', 'confirm', 'billing', 'urgent', 'free-gift', 'bonus', 'airdrop',
  'claim', 'reward', 'refund', 'unlock', 'unusual-activity', 'security-alert'
];

// Homoglyph / Confusable Unicode Character Ranges (Cyrillic, Greek, etc. commonly used in IDN homograph attacks)
const CONFUSABLE_PATTERNS = [
  /[\u0400-\u04FF]/, // Cyrillic
  /[\u0370-\u03FF]/, // Greek
  /[\u0530-\u058F]/, // Armenian
  /[\u0590-\u05FF]/, // Hebrew
  /[\u2000-\u206F]/, // General punctuation / zero-width spaces
  /[\uFEFF]/         // Zero-width no-break space
];

/**
 * Calculate Shannon Entropy of a string (higher = more random/obfuscated)
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const frequencies = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * Compute Levenshtein distance between two strings
 */
function levenshteinDistance(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,      // deletion
        matrix[i][j - 1] + 1,      // insertion
        matrix[i - 1][j - 1] + cost // substitution
      );
    }
  }
  return matrix[a.length][b.length];
}

/**
 * Extract root domain and subdomain from hostname
 */
function parseDomainParts(hostname) {
  const cleanHost = hostname.toLowerCase().trim();
  const parts = cleanHost.split('.');
  if (parts.length <= 1) return { rootDomain: cleanHost, subdomain: '', tld: '' };
  
  const tld = parts[parts.length - 1];
  // Handle two-part TLDs like .co.uk, .com.br
  let rootDomain = '';
  let subdomain = '';
  
  if (parts.length >= 3 && ['co', 'com', 'org', 'net', 'gov', 'edu'].includes(parts[parts.length - 2])) {
    rootDomain = parts.slice(-3).join('.');
    subdomain = parts.slice(0, -3).join('.');
  } else {
    rootDomain = parts.slice(-2).join('.');
    subdomain = parts.slice(0, -2).join('.');
  }
  
  return { rootDomain, subdomain, tld, baseDomainName: parts[parts.length - 2] || '' };
}

/**
 * Probe live SSL certificate on port 443 with timeout
 */
async function probeSSLCertificate(hostname) {
  return new Promise((resolve) => {
    const timeout = 3500;
    let timer = setTimeout(() => {
      resolve({
        valid: false,
        error: 'SSL Handshake timed out',
        hasSSL: false
      });
    }, timeout);

    try {
      const socket = tls.connect({
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false
      }, () => {
        clearTimeout(timer);
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
        const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
        const now = new Date();
        const isExpired = validTo ? now > validTo : false;
        const daysRemaining = validTo ? Math.round((validTo - now) / (1000 * 60 * 60 * 24)) : null;

        socket.destroy();
        resolve({
          valid: authorized && !isExpired,
          authorized,
          isExpired,
          issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown Issuer',
          subject: cert.subject?.CN || hostname,
          validFrom: validFrom ? validFrom.toISOString().split('T')[0] : null,
          validTo: validTo ? validTo.toISOString().split('T')[0] : null,
          daysRemaining,
          hasSSL: true
        });
      });

      socket.on('error', (err) => {
        clearTimeout(timer);
        resolve({
          valid: false,
          error: err.message || 'SSL connection failed',
          hasSSL: false
        });
      });
    } catch (e) {
      clearTimeout(timer);
      resolve({ valid: false, error: e.message, hasSSL: false });
    }
  });
}

/**
 * Resolve live DNS records
 */
async function resolveDNS(hostname) {
  const result = {
    resolved: false,
    aRecords: [],
    mxRecords: [],
    nsRecords: [],
    error: null
  };

  try {
    const aRecords = await dns.resolve4(hostname).catch(() => []);
    const mxRecords = await dns.resolveMx(hostname).catch(() => []);
    const nsRecords = await dns.resolveNs(hostname).catch(() => []);

    result.aRecords = aRecords;
    result.mxRecords = mxRecords.map(m => m.exchange);
    result.nsRecords = nsRecords;
    result.resolved = aRecords.length > 0;
  } catch (err) {
    result.error = err.code || err.message;
  }

  return result;
}

/**
 * Defang a URL (e.g. https://bad.com/file -> hxxps[://]bad[.]com/file)
 */
function defangUrl(inputUrl) {
  return inputUrl
    .replace(/^https:\/\//i, 'hxxps[://]')
    .replace(/^http:\/\//i, 'hxxp[://]')
    .replace(/\./g, '[.]');
}

/**
 * Refang a URL
 */
function refangUrl(defangedUrl) {
  return defangedUrl
    .replace(/^hxxps(\[:\/\/\]|:\/\/)/i, 'https://')
    .replace(/^hxxp(\[:\/\/\]|:\/\/)/i, 'http://')
    .replace(/\[\.\]/g, '.')
    .replace(/\[:\/\/\]/g, '://');
}

/**
 * Normalize common leetspeak substitutions to reveal masked brand names
 * (e.g., paypa1 -> paypal, g00gle -> google)
 */
function normalizeLeetspeak(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/@/g, 'a')
    .replace(/vv/g, 'w');
}

/**
 * Primary URL Risk Analyzer Engine
 */
async function analyzeUrl(rawInput) {
  let cleaned = (rawInput || '').trim();
  if (!cleaned) {
    throw new Error('URL cannot be empty');
  }

  // Auto-prepend http if scheme missing for parsing
  let normalized = cleaned;
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = 'http://' + normalized;
  }

  let parsed;
  try {
    parsed = new url.URL(normalized);
  } catch (err) {
    throw new Error('Invalid URL format');
  }

  const hostname = parsed.hostname;
  const protocol = parsed.protocol.replace(':', '');
  const pathname = parsed.pathname;
  const search = parsed.search;
  const fullPath = pathname + search;
  const originalHadHttps = /^https:\/\//i.test(cleaned);

  const threatsFound = [];
  let score = 0; // 0 (completely safe) to 100 (critical threat)
  const checklist = {
    https: { passed: false, label: 'Secure HTTPS Protocol' },
    dns: { passed: false, label: 'Active DNS Resolution' },
    sslCert: { passed: false, label: 'Valid SSL/TLS Certificate' },
    homographFree: { passed: true, label: 'Clean Character Encoding (No Homoglyphs)' },
    structure: { passed: true, label: 'Standard URL Structure & Depth' },
    reputation: { passed: true, label: 'No Brand Impersonation / Typosquatting' }
  };

  // 1. Exact Whitelist Check for Root Domain
  const { rootDomain, subdomain, tld, baseDomainName } = parseDomainParts(hostname);
  const isTopTrusted = TOP_TRUSTED_DOMAINS.has(rootDomain);

  // 2. IP Address as Hostname Detection
  const isIpv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);
  const isIpv6 = hostname.includes(':');
  if (isIpv4 || isIpv6) {
    score += 45;
    checklist.structure.passed = false;
    threatsFound.push({
      id: 'IP_HOSTNAME',
      severity: 'HIGH',
      category: 'Structural',
      title: 'Raw IP Address Used As Hostname',
      description: `The URL uses a raw IP address (${hostname}) instead of a registered domain name, a technique common in malware Command & Control servers and short-lived phishing landing pages.`
    });
  }

  // 3. Homograph & Punycode Attack Detection
  const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  let hasHomoglyph = false;
  for (const regex of CONFUSABLE_PATTERNS) {
    if (regex.test(hostname)) {
      hasHomoglyph = true;
      break;
    }
  }

  if (isPunycode || hasHomoglyph) {
    score += 65;
    checklist.homographFree.passed = false;
    threatsFound.push({
      id: 'HOMOGRAPH_ATTACK',
      severity: 'CRITICAL',
      category: 'Identity Fraud',
      title: 'IDN Homograph / Confusable Script Detected',
      description: 'The domain contains non-standard unicode characters or punycode mimicking legitimate characters to deceive users visually.'
    });
  }

  // 4. Typosquatting & Brand Impersonation
  let targetedBrand = null;
  let typosquatFound = false;

  for (const brand of TARGET_BRANDS) {
    if (isTopTrusted) break;

    // Check tokens within hostname and baseDomainName (split by hyphens, dots, underscores)
    const tokens = baseDomainName.split(/[-_.]+/).concat(subdomain ? subdomain.split(/[-_.]+/) : []);
    const normalizedHost = normalizeLeetspeak(hostname);
    const normalizedBase = normalizeLeetspeak(baseDomainName);

    // A. Subdomain or hostname incorporating exact brand name
    if (subdomain.includes(brand) || baseDomainName.includes(brand)) {
      targetedBrand = brand;
      score += 55;
      typosquatFound = true;
      checklist.reputation.passed = false;
      threatsFound.push({
        id: 'BRAND_IMPERSONATION',
        severity: 'CRITICAL',
        category: 'Brand Protection',
        title: `Brand Impersonation Target: ${brand.toUpperCase()}`,
        description: `The domain or subdomain incorporates the protected trademark name "${brand}" on an unauthorized host (${rootDomain}).`
      });
      break;
    }

    // B. Leetspeak obfuscation (e.g. paypa1 -> paypal, g00gle -> google)
    if (normalizedHost.includes(brand) || normalizedBase.includes(brand)) {
      targetedBrand = brand;
      score += 65;
      typosquatFound = true;
      checklist.reputation.passed = false;
      threatsFound.push({
        id: 'TYPOSQUATTING',
        severity: 'CRITICAL',
        category: 'Brand Protection',
        title: `Typosquatting Detected: Leetspeak Spoofing "${brand}"`,
        description: `The domain uses character substitution/leetspeak mimicking the authentic brand "${brand}".`
      });
      break;
    }

    // C. Token-level Levenshtein edit distance check (e.g., 'paypa1' token in 'paypa1-security')
    let foundTokenSpoof = false;
    for (const token of tokens) {
      if (!token || token.length < 3) continue;
      const dist = levenshteinDistance(token, brand);
      if (dist === 1 || (dist === 2 && token.length > 5 && brand.length > 5)) {
        targetedBrand = brand;
        score += 60;
        typosquatFound = true;
        foundTokenSpoof = true;
        checklist.reputation.passed = false;
        threatsFound.push({
          id: 'TYPOSQUATTING',
          severity: 'CRITICAL',
          category: 'Brand Protection',
          title: `Typosquatting Detected: Spoofing "${brand}"`,
          description: `The domain token "${token}" is an intentional typo (Levenshtein distance ${dist}) mimicking the authentic brand "${brand}".`
        });
        break;
      }
    }
    if (foundTokenSpoof) break;
  }

  // 5. High-Risk TLD Check
  if (HIGH_RISK_TLDS.has(tld)) {
    score += 25;
    threatsFound.push({
      id: 'HIGH_RISK_TLD',
      severity: 'MEDIUM',
      category: 'Domain Reputation',
      title: `High-Risk Top-Level Domain (.${tld})`,
      description: `The .${tld} TLD has an elevated abuse rate according to global spam and phishing threat feeds.`
    });
  }

  // 6. Suspicious Keyword Extraction in Host and Path
  const lowerUrl = normalized.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(kw => lowerUrl.includes(kw));
  if (matchedKeywords.length > 0 && !isTopTrusted) {
    const kwWeight = Math.min(matchedKeywords.length * 15, 45);
    score += kwWeight;
    threatsFound.push({
      id: 'SUSPICIOUS_KEYWORDS',
      severity: matchedKeywords.length > 2 ? 'HIGH' : 'MEDIUM',
      category: 'Heuristic',
      title: `Suspicious Security Keywords Detected (${matchedKeywords.length})`,
      description: `Found keywords frequently associated with credential harvesting: ${matchedKeywords.join(', ')}.`
    });
  }

  // 7. Structural Obfuscation & Entropy
  const hostEntropy = calculateShannonEntropy(hostname);
  const pathEntropy = calculateShannonEntropy(pathname);
  const subdomainsList = subdomain ? subdomain.split('.') : [];

  if (subdomainsList.length >= 3) {
    score += 20;
    checklist.structure.passed = false;
    threatsFound.push({
      id: 'EXCESSIVE_SUBDOMAINS',
      severity: 'MEDIUM',
      category: 'Structural',
      title: `Excessive Subdomain Depth (${subdomainsList.length} levels)`,
      description: 'Multiple levels of subdomains are frequently deployed to camouflage malicious infrastructure behind bulletproof hosting.'
    });
  }

  if (hostEntropy > 3.9 && !isTopTrusted) {
    score += 20;
    threatsFound.push({
      id: 'HIGH_HOST_ENTROPY',
      severity: 'MEDIUM',
      category: 'Structural',
      title: `High Hostname Randomness/Entropy (${hostEntropy})`,
      description: 'The domain name exhibits mathematical randomness characteristic of Domain Generation Algorithms (DGAs) used by botnets.'
    });
  }

  // @ symbol in URL (auth trick e.g., http://google.com@attacker.com)
  if (cleaned.includes('@')) {
    score += 40;
    checklist.structure.passed = false;
    threatsFound.push({
      id: 'AT_SYMBOL_OBFUSCATION',
      severity: 'HIGH',
      category: 'Deception',
      title: 'Credential/UserInfo "@" Obfuscation Trick',
      description: 'The URL uses the "@" symbol before the host, tricking users into thinking the prefix is the destination host.'
    });
  }

  // 8. Protocol & Port Checks
  if (originalHadHttps) {
    checklist.https.passed = true;
  } else {
    score += 15;
    checklist.https.passed = false;
    threatsFound.push({
      id: 'INSECURE_HTTP',
      severity: 'LOW',
      category: 'Transport Security',
      title: 'Unencrypted HTTP Connection',
      description: 'The URL does not use SSL/TLS encryption. Sensitive traffic can be intercepted or manipulated via Man-In-The-Middle (MITM) attacks.'
    });
  }

  if (parsed.port && !['80', '443'].includes(parsed.port)) {
    score += 15;
    threatsFound.push({
      id: 'NON_STANDARD_PORT',
      severity: 'LOW',
      category: 'Network',
      title: `Non-Standard Port :${parsed.port}`,
      description: 'Web traffic is routed over an unusual port rather than standard ports 80/443.'
    });
  }

  // 9. Live DNS Probe
  let dnsResults = { resolved: false, aRecords: [], mxRecords: [], nsRecords: [] };
  if (!isIpv4 && !isIpv6) {
    dnsResults = await resolveDNS(hostname);
    if (dnsResults.resolved) {
      checklist.dns.passed = true;
    } else {
      score += 20;
      threatsFound.push({
        id: 'DNS_RESOLUTION_FAILED',
        severity: 'MEDIUM',
        category: 'Network',
        title: 'Domain DNS Fails to Resolve (NXDOMAIN or Inactive)',
        description: 'The domain does not have active A or AAAA records. It may be dead, newly registered without hosting, or taken down by registrars.'
      });
    }
  } else {
    checklist.dns.passed = true;
  }

  // 10. Live SSL Certificate Handshake Probe
  let sslDetails = { valid: false, hasSSL: false };
  if (!isIpv4 && !isIpv6 && (originalHadHttps || checklist.dns.passed)) {
    sslDetails = await probeSSLCertificate(hostname);
    if (sslDetails.hasSSL && sslDetails.valid) {
      checklist.sslCert.passed = true;
    } else if (sslDetails.isExpired) {
      score += 30;
      threatsFound.push({
        id: 'EXPIRED_SSL_CERT',
        severity: 'HIGH',
        category: 'Transport Security',
        title: 'Expired SSL Certificate',
        description: `The SSL certificate for this host expired on ${sslDetails.validTo}.`
      });
    }
  }

  // Whitelist Dampener: if top trusted domain and NO malicious spoofing detected
  if (isTopTrusted && !typosquatFound && !hasHomoglyph && !isPunycode) {
    score = Math.min(score, 5); // Near-zero risk for authentic major platforms
    checklist.reputation.passed = true;
  }

  // Cap Score between 0 and 100
  score = Math.min(Math.max(Math.round(score), 0), 100);

  // Determine Severity Level
  let riskLevel = 'Safe';
  let riskColor = 'green';
  if (score >= 75) {
    riskLevel = 'Malicious';
    riskColor = 'red';
  } else if (score >= 45) {
    riskLevel = 'Suspicious';
    riskColor = 'amber';
  } else if (score >= 20) {
    riskLevel = 'Low Risk';
    riskColor = 'blue';
  } else {
    riskLevel = 'Safe';
    riskColor = 'emerald';
  }

  // Generate Recommendations
  const recommendations = [];
  if (score >= 70) {
    recommendations.push('Do NOT visit this website or click any links from it.');
    recommendations.push('Never submit credentials, banking information, or passwords.');
    recommendations.push('If received via email or SMS, mark as phishing and report to your administrator.');
  } else if (score >= 40) {
    recommendations.push('Exercise caution. Verify the sender and ensure this domain is authentic.');
    recommendations.push('Inspect the SSL certificate and look for an authentic padlock in your browser.');
    recommendations.push('Do not download executable files or permit browser notifications.');
  } else {
    recommendations.push('The URL passes standard heuristic and reputation checks.');
    recommendations.push('Always ensure you are using a modern browser with automatic malware blocking enabled.');
  }

  return {
    url: cleaned,
    normalizedUrl: parsed.toString(),
    defangedUrl: defangUrl(cleaned),
    riskScore: score,
    riskLevel,
    riskColor,
    hostname,
    rootDomain,
    subdomain: subdomain || null,
    tld,
    protocol,
    pathname,
    entropy: {
      host: hostEntropy,
      path: pathEntropy
    },
    checklist,
    threatsFound,
    dns: {
      resolved: dnsResults.resolved,
      ipAddresses: dnsResults.aRecords,
      mailServers: dnsResults.mxRecords,
      nameServers: dnsResults.nsRecords
    },
    ssl: sslDetails,
    targetedBrand,
    recommendations,
    scannedAt: new Date().toISOString()
  };
}

module.exports = {
  analyzeUrl,
  defangUrl,
  refangUrl,
  calculateShannonEntropy,
  levenshteinDistance
};
