# Creating the Node.js gate-evaluator script file and a README that explains usage.
script = r'''
#!/usr/bin/env node
/**
 * gate-evaluator.js
 *
 * Evaluator for cloud-native gates described in GATE_SPECIFICATIONS.md
 *
 * Usage:
 *   node gate-evaluator.js --snyk <snyk-results-dir> --sonar <sonar-results-dir> --thresholds <thresholds.json> --output <gate-result.json>
 *
 * The script:
 *  - Loads base thresholds (embedded)
 *  - Loads optional thresholds.json from repo (overrides, must be stricter)
 *  - Reads Snyk JSON results from provided directory (searches common filenames)
 *  - Reads Sonar results from provided directory (searches common filenames)
 *  - Evaluates gates: gatr-01, gatr-02, gatr-03, gatr-07, gatr-08, gatr-09, gatr-10, gatr-14
 *  - Writes gating result JSON and exits with code 0 (pass/warn) or 1 (fail enforcing)
 *
 * Notes:
 *  - This script tries to be defensive: if required data isn't present it will WARN rather than FAIL for NON_ENFORCING gates.
 *  - ENFORCING gates will FAIL when conditions matched unless a Jira exception file is provided (not implemented here).
 *
 * Output format: {
 *   final_decision: "PASS" | "WARN" | "FAIL" | "PASS_WITH_EXCEPTION",
 *   gates: [ { id, status, details... } ]
 * }
 */
const fs = require('fs');
const path = require('path');

function readJsonIfExists(p) {
  try {
    if (!p) return null;
    if (!fs.existsSync(p)) return null;
    const txt = fs.readFileSync(p, 'utf8');
    return JSON.parse(txt);
  } catch (e) {
    console.error('Failed to read/parse JSON', p, e.message);
    return null;
  }
}

function findFileInDir(dir, patterns) {
  if (!dir) return null;
  try {
    const files = fs.readdirSync(dir);
    for (const p of patterns) {
      const found = files.find(f => f.toLowerCase() === p.toLowerCase());
      if (found) return path.join(dir, found);
    }
    // try contains patterns
    for (const f of files) {
      for (const pat of patterns) {
        if (f.toLowerCase().includes(pat.toLowerCase())) return path.join(dir, f);
      }
    }
    return null;
  } catch (e) {
    return null;
  }
}

function loadSnykResults(dir) {
  // Common filenames
  const candidates = ['snyk-results.json', 'snyk-output.json', 'results.json', 'security-results.json'];
  const file = findFileInDir(dir, candidates);
  if (!file) return null;
  return readJsonIfExists(file);
}

function loadSonarResults(dir) {
  // Sonar might produce project_status or a custom json. Try common names.
  const candidates = ['sonar-report.json', 'sonar-results.json', 'project_status.json', 'sonar-quality.json', 'scan-report.json'];
  const file = findFileInDir(dir, candidates);
  if (!file) return null;
  return readJsonIfExists(file);
}

function metricRatingToNumber(r) {
  if (!r) return 99;
  const map = { 'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5 };
  return map[r] || 99;
}

function loadBaseThresholds() {
  return {
    snyk: { critical: 0, high: 5, medium: 20 },
    sonarqube: {
      coverage: 80,
      bugs: 5,
      vulnerabilities: 0,
      code_smells: 50,
      security_rating: 'A',
      reliability_rating: 'A',
      maintainability_rating: 'B',
      tech_debt_minutes: 480,
      express_lane: {
        coverage_threshold: 80,
        test_success_threshold: 80,
        max_security_rating: 'B',
        max_reliability_rating: 'C'
      }
    },
    approved_sonar_params: ['sonar.coverage.exclusions','sonar.cpd.exclusions']
  };
}

function mergeThresholds(base, overrides) {
  if (!overrides) return base;
  const merged = JSON.parse(JSON.stringify(base));
  if (overrides.snyk) {
    merged.snyk = Object.assign({}, merged.snyk, overrides.snyk);
  }
  if (overrides.sonarqube) {
    merged.sonarqube = Object.assign({}, merged.sonarqube, overrides.sonarqube);
  }
  return merged;
}

function evaluateSnykGates(snykJson, thresholds) {
  // Expect snykJson.vulnerabilities array
  const result = [];
  const vulns = (snykJson && snykJson.vulnerabilities) ? snykJson.vulnerabilities : [];
  const bySeverity = { critical:0, high:0, medium:0, low:0 };
  if (Array.isArray(vulns)) {
    for (const v of vulns) {
      const sev = (v.severity || v.issueSeverity || '').toLowerCase();
      if (bySeverity[sev] !== undefined) bySeverity[sev]++;
      else if (v.cvssScore) {
        const cv = Number(v.cvssScore || v.cvss || 0);
        if (cv >= 9) bySeverity.critical++;
        else if (cv >=7) bySeverity.high++;
        else if (cv >=4) bySeverity.medium++;
      }
    }
  }

  // gatr-03 Critical (non-enforcing but zero tolerance)
  if (bySeverity.critical > 0) {
    result.push({ id: 'gatr-03', status: 'WARN', critical_vulnerabilities: bySeverity.critical, threshold: thresholds.snyk.critical, message: 'Critical vulnerabilities detected - immediate attention required' });
  } else {
    result.push({ id: 'gatr-03', status: 'PASS', critical_vulnerabilities: 0, threshold: thresholds.snyk.critical });
  }

  // gatr-01 High
  if (bySeverity.high > thresholds.snyk.high) {
    result.push({ id: 'gatr-01', status: 'WARN', high_vulnerabilities: bySeverity.high, threshold: thresholds.snyk.high, message: 'High vulnerabilities exceed threshold' });
  } else {
    result.push({ id: 'gatr-01', status: 'PASS', high_vulnerabilities: bySeverity.high, threshold: thresholds.snyk.high });
  }

  // gatr-02 Medium
  if (bySeverity.medium > thresholds.snyk.medium) {
    result.push({ id: 'gatr-02', status: 'WARN', medium_vulnerabilities: bySeverity.medium, threshold: thresholds.snyk.medium, message: 'Medium vulnerabilities exceed threshold' });
  } else {
    result.push({ id: 'gatr-02', status: 'PASS', medium_vulnerabilities: bySeverity.medium, threshold: thresholds.snyk.medium });
  }

  return result;
}

function evaluateSonarGates(sonarJson, thresholds, options) {
  // sonarJson may be SonarCloud project_status or a custom metrics blob.
  const result = [];
  const sonarMetrics = (sonarJson && sonarJson.projectStatus) ? sonarJson.projectStatus : sonarJson;

  // Extract key metrics defensively
  let coverage = null, bugs = null, vulnerabilities = null, code_smells = null, ratings = {};
  // If Sonar's project_status with conditions:
  if (sonarMetrics && sonarMetrics.conditions && Array.isArray(sonarMetrics.conditions)) {
    for (const c of sonarMetrics.conditions) {
      if (c.metricKey === 'coverage') coverage = Number(c.actualValue);
      if (c.metricKey === 'new_coverage') coverage = Number(c.actualValue);
      if (c.metricKey === 'bugs') bugs = Number(c.actualValue);
      if (c.metricKey === 'vulnerabilities') vulnerabilities = Number(c.actualValue);
      if (c.metricKey === 'code_smells') code_smells = Number(c.actualValue);
    }
    if (sonarMetrics.status) {
      ratings.quality_gate_status = sonarMetrics.status;
    }
  } else if (sonarJson && typeof sonarJson === 'object') {
    // Try many possible shapes: metrics, measures, etc.
    if (sonarJson.metrics) {
      coverage = sonarJson.metrics.coverage || coverage;
      bugs = sonarJson.metrics.bugs || bugs;
      vulnerabilities = sonarJson.metrics.vulnerabilities || vulnerabilities;
      code_smells = sonarJson.metrics.code_smells || code_smells;
      if (sonarJson.metrics.ratings) ratings = sonarJson.metrics.ratings;
    }
    // fallback for the sample shape used earlier
    if (sonarJson.metrics && sonarJson.metrics.coverage !== undefined) coverage = sonarJson.metrics.coverage;
    if (sonarJson.qualityGate && sonarJson.qualityGate.status) ratings.quality_gate_status = sonarJson.qualityGate.status;
    if (sonarJson.metrics && sonarJson.metrics.ratings) ratings = sonarJson.metrics.ratings;
  }

  // gatr-07 Developer thresholds (NON_ENFORCING)
  const g07_issues = [];
  if (coverage !== null && coverage < thresholds.sonarqube.coverage) {
    g07_issues.push(`Coverage ${coverage}% < ${thresholds.sonarqube.coverage}%`);
  }
  if (bugs !== null && bugs > thresholds.sonarqube.bugs) {
    g07_issues.push(`Bugs ${bugs} > ${thresholds.sonarqube.bugs}`);
  }
  if (vulnerabilities !== null && vulnerabilities > thresholds.sonarqube.vulnerabilities) {
    g07_issues.push(`Vulnerabilities ${vulnerabilities} > ${thresholds.sonarqube.vulnerabilities}`);
  }
  if (code_smells !== null && code_smells > thresholds.sonarqube.code_smells) {
    g07_issues.push(`Code smells ${code_smells} > ${thresholds.sonarqube.code_smells}`);
  }
  if (g07_issues.length > 0) {
    result.push({ id: 'gatr-07', status: 'WARN', issues: g07_issues });
  } else {
    result.push({ id: 'gatr-07', status: 'PASS' });
  }

  // gatr-08 Code Quality (ENFORCING)
  // Trigger FAIL if quality gate status is ERROR or blocker issues > 0
  let g08_status = 'PASS';
  const g08_details = {};
  const qStatus = (ratings.quality_gate_status || '').toUpperCase();
  if (qStatus === 'ERROR' || qStatus === 'FAIL' ) {
    g08_status = 'FAIL';
    g08_details.message = 'Sonar Quality Gate status: ' + qStatus;
  }
  // also check for blocker issues if provided (some reports list blocker_issues)
  if (sonarJson && sonarJson.projectStatus && Array.isArray(sonarJson.projectStatus.conditions)) {
    const blockers = sonarJson.projectStatus.conditions.filter(c => (c.metricKey||'').includes('blocker') && c.status === 'ERROR');
    if (blockers.length > 0) {
      g08_status = 'FAIL';
      g08_details.blockers = blockers;
      g08_details.message = 'Blocker issues detected';
    }
  }
  result.push(Object.assign({ id: 'gatr-08', status: g08_status }, g08_details));

  // gatr-09 Approved Sonar Parameters (ENFORCING)
  // We will try to read a sonar-params file if provided in options.paramsFile
  const usedParams = options.sonarParams || [];
  const disallowed = usedParams.filter(p => !thresholds.approved_sonar_params.includes(p));
  if (disallowed.length > 0) {
    result.push({ id: 'gatr-09', status: 'FAIL', disallowed_parameters: disallowed, allowed_parameters: thresholds.approved_sonar_params });
  } else {
    result.push({ id: 'gatr-09', status: 'PASS', parameters_used: usedParams });
  }

  // gatr-10 Express Lane (NON_ENFORCING)
  const expressIssues = [];
  if (coverage !== null && coverage < thresholds.sonarqube.express_lane.coverage_threshold) {
    expressIssues.push(`Coverage ${coverage}% < ${thresholds.sonarqube.express_lane.coverage_threshold}%`);
  }
  // test_success_density may be present as metrics.test_success_density
  const test_success_density = sonarJson && sonarJson.metrics && sonarJson.metrics.test_success_density;
  if (test_success_density !== undefined && test_success_density < thresholds.sonarqube.express_lane.test_success_threshold) {
    expressIssues.push(`Test success density ${test_success_density}% < ${thresholds.sonarqube.express_lane.test_success_threshold}%`);
  }
  // ratings checks - try to read from ratings object
  if (ratings.security && metricRatingToNumber(ratings.security) > metricRatingToNumber(thresholds.sonarqube.express_lane.max_security_rating)) {
    expressIssues.push(`Security rating ${ratings.security} worse than allowed ${thresholds.sonarqube.express_lane.max_security_rating}`);
  }
  if (ratings.reliability && metricRatingToNumber(ratings.reliability) > metricRatingToNumber(thresholds.sonarqube.express_lane.max_reliability_rating)) {
    expressIssues.push(`Reliability rating ${ratings.reliability} worse than allowed ${thresholds.sonarqube.express_lane.max_reliability_rating}`);
  }
  if (expressIssues.length > 0) {
    result.push({ id: 'gatr-10', status: 'WARN', warnings: expressIssues });
  } else {
    result.push({ id: 'gatr-10', status: 'PASS' });
  }

  return result;
}

function evaluateBranchGate(env, options) {
  // gatr-14: ENFORCING
  const branchRef = env.GITHUB_REF || env.GITHUB_BRANCH || '';
  const targetEnv = env.TARGET_ENVIRONMENT || options.target || '';
  const allowedPatterns = [/^refs\/heads\/main$/, /^refs\/heads\/release\/.+$/];

  const isAllowed = allowedPatterns.some(p => p.test(branchRef));
  if ((targetEnv === 'PROD' || targetEnv === 'UAT') && !isAllowed) {
    return { id: 'gatr-14', status: 'FAIL', branch: branchRef, environment: targetEnv, message: 'Only main or release/* branches can deploy to UAT/PROD' };
  }
  return { id: 'gatr-14', status: 'PASS', branch: branchRef, environment: targetEnv };
}

function decideFinal(gates) {
  // If any ENFORCING gate is FAIL -> overall FAIL
  // ENFORCING: gatr-08, gatr-09, gatr-14
  const enforcingIds = ['gatr-08','gatr-09','gatr-14'];
  let final = 'PASS';
  for (const g of gates) {
    if (enforcingIds.includes(g.id) && g.status === 'FAIL') {
      final = 'FAIL';
      return final;
    }
    if (g.status === 'WARN' && final !== 'FAIL') {
      final = 'WARN';
    }
  }
  return final;
}

// ---------------------
// CLI parsing
// ---------------------
const argv = require('minimist')(process.argv.slice(2), {
  string: ['snyk','sonar','thresholds','output','sonar-params-file','target'],
  alias: { s:'snyk', q:'sonar', t:'thresholds', o:'output' },
  default: {}
});

const snykDir = argv.snyk;
const sonarDir = argv.sonar;
const thresholdsFile = argv.thresholds;
const outFile = argv.output || 'gating/gate-result.json';
const sonarParamsFile = argv['sonar-params-file'];
const target = argv.target || process.env.TARGET_ENVIRONMENT;

const baseThresholds = loadBaseThresholds();
const repoOverrides = readJsonIfExists(thresholdsFile);
const thresholds = mergeThresholds(baseThresholds, repoOverrides);

const snykJson = loadSnykResults(snykDir);
const sonarJson = loadSonarResults(sonarDir);

let sonarParams = [];
if (sonarParamsFile && fs.existsSync(sonarParamsFile)) {
  try {
    sonarParams = JSON.parse(fs.readFileSync(sonarParamsFile,'utf8'));
    if (!Array.isArray(sonarParams)) sonarParams = [];
  } catch(e) { sonarParams = []; }
}

// Evaluate
const gateResults = [];
gateResults.push(...evaluateSnykGates(snykJson, thresholds));
gateResults.push(...evaluateSonarGates(sonarJson, thresholds, { sonarParams, target }));
gateResults.push(evaluateBranchGate(process.env, { target }));

const finalDecision = decideFinal(gateResults);

// Ensure output dir exists
try {
  const outDir = path.dirname(outFile);
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify({ final_decision: finalDecision, gates: gateResults }, null, 2), 'utf8');
  console.log('Gate result written to', outFile);
} catch (e) {
  console.error('Failed to write output', e.message);
  process.exit(2);
}

// Exit codes: 0 for PASS/WARN/PASS_WITH_EXCEPTION, 1 for FAIL
if (finalDecision === 'FAIL') {
  console.error('Gate evaluation result: FAIL');
  process.exit(1);
} else {
  console.log('Gate evaluation result:', finalDecision);
  process.exit(0);
}
'''.strip()

readme = r'''
Gate Evaluator - README
-----------------------

Files created:
 - /mnt/data/gate-evaluator.js

How to use in GitHub Actions:
 - Place this script in repository under scripts/gate-evaluator.js
 - Make sure Node.js is available in runner (ubuntu-latest has node)
 - Example step:

    - name: Run Gate Evaluator
      run: |
        chmod +x scripts/gate-evaluator.js
        node scripts/gate-evaluator.js \
          --snyk "gating/security/unzipped" \
          --sonar "gating/quality/unzipped" \
          --thresholds "thresholds.json" \
          --sonar-params-file "gating/quality/sonar-params.json" \
          --output "gating/gate-result.json"

Notes:
 - The script expects Snyk JSON with a 'vulnerabilities' array and Sonar results in common names (sonar-report.json, sonar-results.json, project_status.json).
 - Adjust paths as needed.
 - If you want, I can also generate a Python version or a more extensive test harness that runs locally against your uploaded zip files.
'''

# Write files to /mnt/data
import os
os.makedirs('/mnt/data/scripts', exist_ok=True)
with open('/mnt/data/scripts/gate-evaluator.js', 'w', encoding='utf8') as f:
    f.write(script)
with open('/mnt/data/scripts/GATE_EVALUATOR_README.md', 'w', encoding='utf8') as f:
    f.write(readme)

# Provide download link to user
print("Created /mnt/data/scripts/gate-evaluator.js and README")
print("Download the script: sandbox:/mnt/data/scripts/gate-evaluator.js")
print("Download the README: sandbox:/mnt/data/scripts/GATE_EVALUATOR_README.md")

