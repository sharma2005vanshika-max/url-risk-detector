const fs = require('fs');
const path = require('path');

// Try loading environment variables from .env in server or parent
function loadEnv() {
  const envPaths = [
    path.resolve(__dirname, '.env'),
    path.resolve(__dirname, '../.env'),
    path.resolve(__dirname, '../../.env.local')
  ];
  for (const envPath of envPaths) {
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, 'utf8');
        content.split('\n').forEach(line => {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) return;
          const idx = trimmed.indexOf('=');
          if (idx !== -1) {
            const key = trimmed.slice(0, idx).trim();
            const val = trimmed.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
            if (!process.env[key]) {
              process.env[key] = val;
            }
          }
        });
      } catch (e) {
        // ignore read error
      }
    }
  }
}
loadEnv();

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY || process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || '';

const isSupabaseConfigured = Boolean(SUPABASE_URL && SUPABASE_KEY);

// Local fallback database file
const LOCAL_DB_PATH = path.resolve(__dirname, 'local_scan_logs.json');

function loadLocalLogs() {
  try {
    if (fs.existsSync(LOCAL_DB_PATH)) {
      const data = JSON.parse(fs.readFileSync(LOCAL_DB_PATH, 'utf8'));
      if (Array.isArray(data)) return data;
    }
  } catch (e) {
    console.warn('[DB] Could not read local scan logs:', e.message);
  }
  return [];
}

function saveLocalLogs(logs) {
  try {
    fs.writeFileSync(LOCAL_DB_PATH, JSON.stringify(logs.slice(0, 100), null, 2));
  } catch (e) {
    console.warn('[DB] Could not write local scan logs:', e.message);
  }
}

let localLogsCache = loadLocalLogs();

if (isSupabaseConfigured) {
  console.log(`[DB] Supabase integration ACTIVE: ${SUPABASE_URL}`);
} else {
  console.log('[DB] Supabase credentials not set — using local persistent file store.');
}

/**
 * Save a scan result to database
 */
async function saveScanLog(scanData, clientIp = 'Unknown') {
  const row = {
    url: scanData.url,
    hostname: scanData.hostname || '',
    root_domain: scanData.rootDomain || '',
    risk_score: Number(scanData.riskScore) || 0,
    risk_level: scanData.riskLevel || 'Safe',
    risk_color: scanData.riskColor || 'emerald',
    tld: scanData.tld || '',
    protocol: scanData.protocol || 'http',
    threat_count: scanData.threatsFound ? scanData.threatsFound.length : 0,
    threats: scanData.threatsFound || [],
    targeted_brand: scanData.targetedBrand || null,
    dns_resolved: Boolean(scanData.dns && scanData.dns.resolved),
    ssl_valid: Boolean(scanData.ssl && scanData.ssl.valid),
    user_ip: clientIp,
    created_at: new Date().toISOString()
  };

  // Always keep in local memory/file
  localLogsCache.unshift({ id: 'local_' + Date.now(), ...row });
  if (localLogsCache.length > 200) localLogsCache = localLogsCache.slice(0, 200);
  saveLocalLogs(localLogsCache);

  if (!isSupabaseConfigured) {
    return row;
  }

  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/scan_logs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Prefer': 'return=representation'
      },
      body: JSON.stringify(row)
    });

    if (!res.ok) {
      const errText = await res.text();
      console.warn('[DB] Supabase insert warning:', res.status, errText);
    } else {
      console.log(`[DB] Logged scan for ${row.url} to Supabase successfully`);
    }
  } catch (err) {
    console.warn('[DB] Supabase insert error:', err.message);
  }

  return row;
}

/**
 * Fetch latest global scans (across all users)
 */
async function getRecentScans(limit = 50) {
  if (isSupabaseConfigured) {
    try {
      const url = `${SUPABASE_URL}/rest/v1/scan_logs?select=*&order=created_at.desc&limit=${limit}`;
      const res = await fetch(url, {
        headers: {
          'apikey': SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`
        }
      });
      if (res.ok) {
        const rows = await res.json();
        if (Array.isArray(rows) && rows.length > 0) {
          return rows;
        }
      }
    } catch (e) {
      console.warn('[DB] Supabase getRecentScans error, falling back to local:', e.message);
    }
  }
  return localLogsCache.slice(0, limit);
}

/**
 * Fetch aggregated statistics across all scans
 */
async function getGlobalStats() {
  const logs = await getRecentScans(200);
  const total = logs.length;
  const safeCount = logs.filter(l => l.risk_level === 'Safe' || l.risk_level === 'Low Risk').length;
  const suspiciousCount = logs.filter(l => l.risk_level === 'Suspicious').length;
  const maliciousCount = logs.filter(l => l.risk_level === 'Malicious').length;
  const avgScore = total > 0 ? Math.round(logs.reduce((acc, l) => acc + (l.risk_score || 0), 0) / total) : 0;

  // Count targeted brands
  const brandCounts = {};
  logs.forEach(l => {
    if (l.targeted_brand) {
      brandCounts[l.targeted_brand] = (brandCounts[l.targeted_brand] || 0) + 1;
    }
  });
  const topBrands = Object.entries(brandCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([brand, count]) => ({ brand, count }));

  // Count abused TLDs
  const tldCounts = {};
  logs.forEach(l => {
    if (l.tld) {
      tldCounts[l.tld] = (tldCounts[l.tld] || 0) + 1;
    }
  });
  const topTlds = Object.entries(tldCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([tld, count]) => ({ tld, count }));

  return {
    total,
    safeCount,
    suspiciousCount,
    maliciousCount,
    avgScore,
    topBrands,
    topTlds,
    isSupabaseConnected: isSupabaseConfigured
  };
}

module.exports = {
  saveScanLog,
  getRecentScans,
  getGlobalStats,
  isSupabaseConfigured
};
