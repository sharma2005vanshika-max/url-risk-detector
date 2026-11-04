const { analyzeUrl, defangUrl, refangUrl, calculateShannonEntropy, levenshteinDistance } = require('./analyzer');

async function runTests() {
  console.log('--- Starting URL Risk Detector Test Suite ---\n');

  // Test 1: Levenshtein distance
  const d1 = levenshteinDistance('paypal', 'paypa1');
  console.assert(d1 === 1, `Expected edit distance 1, got ${d1}`);
  console.log('✓ Levenshtein distance test passed');

  // Test 2: Defanging
  const defanged = defangUrl('https://malicious.com/download.exe');
  console.assert(defanged === 'hxxps[://]malicious[.]com/download[.]exe', `Defang mismatch: ${defanged}`);
  const refanged = refangUrl(defanged);
  console.assert(refanged === 'https://malicious.com/download.exe', `Refang mismatch: ${refanged}`);
  console.log('✓ Defang / Refang test passed');

  // Test 3: Safe top domain
  console.log('\nAnalyzing Safe URL: https://github.com/trending ...');
  const safeRes = await analyzeUrl('https://github.com/trending');
  console.log(`> Risk Score: ${safeRes.riskScore}/100, Level: ${safeRes.riskLevel}`);
  console.assert(safeRes.riskScore <= 15, `Expected safe score <= 15, got ${safeRes.riskScore}`);
  console.assert(safeRes.riskLevel === 'Safe', `Expected Safe level, got ${safeRes.riskLevel}`);
  console.log('✓ Whitelisted safe domain test passed');

  // Test 4: Brand Spoofing / Typosquatted domain
  console.log('\nAnalyzing Typosquat URL: http://paypa1-security-verification.xyz/login ...');
  const typoRes = await analyzeUrl('http://paypa1-security-verification.xyz/login');
  console.log(`> Risk Score: ${typoRes.riskScore}/100, Level: ${typoRes.riskLevel}, Threats: ${typoRes.threatsFound.map(t => t.id).join(', ')}`);
  console.assert(typoRes.riskScore >= 70, `Expected malicious score >= 70, got ${typoRes.riskScore}`);
  console.assert(typoRes.threatsFound.some(t => t.id === 'TYPOSQUATTING' || t.id === 'BRAND_IMPERSONATION'), 'Expected brand threat');
  console.log('✓ Brand typosquatting detection passed');

  // Test 5: Homograph unicode attack
  console.log('\nAnalyzing Homograph URL: http://аррӏе.com/login ...');
  const homoRes = await analyzeUrl('http://аррӏе.com/login');
  console.log(`> Risk Score: ${homoRes.riskScore}/100, Level: ${homoRes.riskLevel}, Threats: ${homoRes.threatsFound.map(t => t.id).join(', ')}`);
  console.assert(homoRes.riskScore >= 65, `Expected score >= 65, got ${homoRes.riskScore}`);
  console.assert(homoRes.threatsFound.some(t => t.id === 'HOMOGRAPH_ATTACK'), 'Expected homograph threat');
  console.log('✓ Homograph detection passed');

  // Test 6: Raw IP address hostname
  console.log('\nAnalyzing Raw IP URL: http://192.168.1.1/update ...');
  const ipRes = await analyzeUrl('http://192.168.1.1/update');
  console.log(`> Risk Score: ${ipRes.riskScore}/100, Level: ${ipRes.riskLevel}, Threats: ${ipRes.threatsFound.map(t => t.id).join(', ')}`);
  console.assert(ipRes.riskScore >= 50, `Expected score >= 50, got ${ipRes.riskScore}`);
  console.assert(ipRes.threatsFound.some(t => t.id === 'IP_HOSTNAME'), 'Expected IP hostname threat');
  console.log('✓ Raw IP hostname test passed');

  console.log('\n========================================');
  console.log('ALL URL RISK DETECTOR UNIT TESTS PASSED!');
  console.log('========================================\n');
}

runTests().catch((err) => {
  console.error('Test failed with error:', err);
  process.exit(1);
});
