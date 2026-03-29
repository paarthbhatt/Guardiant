#!/usr/bin/env node

/**
 * Guardiant Metrics Collection Script
 * 
 * Collects daily metrics from GitHub, NPM, and stores them in a CSV file.
 * Can be extended to sync with Notion, PostHog, or other services.
 * 
 * Usage:
 *   node .automation/scripts/collect-metrics.js
 * 
 * Environment Variables (optional):
 *   NOTION_API_KEY - For Notion sync
 *   NOTION_DATABASE_ID - Notion database ID
 *   POSTHOG_API_KEY - For PostHog analytics
 */

const fs = require('fs');
const path = require('path');

const REPO = 'paarthbhatt/Guardiant';
const NPM_PACKAGE = '@guardiant/cli';
const METRICS_FILE = path.join(__dirname, '..', 'data', 'metrics.csv');

// ANSI colors for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

async function fetchWithTimeout(url, options = {}) {
  const timeout = options.timeout || 10000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Guardiant-Metrics-Collector/1.0',
        ...options.headers,
      },
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

async function getGitHubStats() {
  try {
    const response = await fetchWithTimeout(`https://api.github.com/repos/${REPO}`);
    
    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    return {
      stars: data.stargazers_count,
      forks: data.forks_count,
      watchers: data.subscribers_count,
      openIssues: data.open_issues_count,
      language: data.language,
      license: data.license?.spdx_id || 'Unknown',
      updatedAt: data.updated_at,
    };
  } catch (error) {
    console.error(`${colors.red}Error fetching GitHub stats:${colors.reset}`, error.message);
    return null;
  }
}

async function getNPMStats() {
  try {
    // Get last day downloads
    const dayResponse = await fetchWithTimeout(
      `https://api.npmjs.org/downloads/point/last-day/${NPM_PACKAGE}`
    );
    
    // Get last week downloads
    const weekResponse = await fetchWithTimeout(
      `https://api.npmjs.org/downloads/point/last-week/${NPM_PACKAGE}`
    );
    
    // Get last month downloads
    const monthResponse = await fetchWithTimeout(
      `https://api.npmjs.org/downloads/point/last-month/${NPM_PACKAGE}`
    );
    
    if (!dayResponse.ok || !weekResponse.ok || !monthResponse.ok) {
      throw new Error('NPM API error');
    }
    
    const dayData = await dayResponse.json();
    const weekData = await weekResponse.json();
    const monthData = await monthResponse.json();
    
    return {
      downloadsDay: dayData.downloads,
      downloadsWeek: weekData.downloads,
      downloadsMonth: monthData.downloads,
      periodStart: monthData.start,
      periodEnd: monthData.end,
    };
  } catch (error) {
    console.error(`${colors.red}Error fetching NPM stats:${colors.reset}`, error.message);
    return null;
  }
}

function ensureDataDirectory() {
  const dataDir = path.dirname(METRICS_FILE);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log(`${colors.green}Created data directory:${colors.reset} ${dataDir}`);
  }
}

function initializeCSV() {
  if (!fs.existsSync(METRICS_FILE)) {
    const header = 'date,stars,forks,watchers,open_issues,downloads_day,downloads_week,downloads_month,notes\n';
    fs.writeFileSync(METRICS_FILE, header);
    console.log(`${colors.green}Initialized metrics CSV:${colors.reset} ${METRICS_FILE}`);
  }
}

function appendToCSV(metrics) {
  const date = new Date().toISOString().split('T')[0];
  const row = [
    date,
    metrics.github?.stars || 0,
    metrics.github?.forks || 0,
    metrics.github?.watchers || 0,
    metrics.github?.openIssues || 0,
    metrics.npm?.downloadsDay || 0,
    metrics.npm?.downloadsWeek || 0,
    metrics.npm?.downloadsMonth || 0,
    '', // notes placeholder
  ].join(',');
  
  fs.appendFileSync(METRICS_FILE, row + '\n');
  console.log(`${colors.green}Appended metrics to CSV${colors.reset}`);
}

function displayMetrics(github, npm) {
  console.log('\n' + colors.cyan + '═══════════════════════════════════════════════════════════════' + colors.reset);
  console.log(colors.cyan + '  📊 Guardiant Daily Metrics Report' + colors.reset);
  console.log(colors.cyan + '═══════════════════════════════════════════════════════════════' + colors.reset);
  console.log('');
  console.log(colors.yellow + 'GitHub Repository Stats:' + colors.reset);
  if (github) {
    console.log(`  Stars:        ${colors.green}${github.stars.toLocaleString()}${colors.reset}`);
    console.log(`  Forks:        ${colors.green}${github.forks.toLocaleString()}${colors.reset}`);
    console.log(`  Watchers:     ${colors.green}${github.watchers.toLocaleString()}${colors.reset}`);
    console.log(`  Open Issues:  ${colors.yellow}${github.openIssues.toLocaleString()}${colors.reset}`);
  } else {
    console.log(`  ${colors.red}Unable to fetch GitHub stats${colors.reset}`);
  }
  console.log('');
  console.log(colors.yellow + 'NPM Package Stats:' + colors.reset);
  if (npm) {
    console.log(`  Downloads (Today):  ${colors.green}${npm.downloadsDay.toLocaleString()}${colors.reset}`);
    console.log(`  Downloads (Week):   ${colors.green}${npm.downloadsWeek.toLocaleString()}${colors.reset}`);
    console.log(`  Downloads (Month):  ${colors.green}${npm.downloadsMonth.toLocaleString()}${colors.reset}`);
  } else {
    console.log(`  ${colors.red}Unable to fetch NPM stats${colors.reset}`);
  }
  console.log('');
  console.log(colors.cyan + '═══════════════════════════════════════════════════════════════' + colors.reset);
  console.log(`  Timestamp: ${new Date().toISOString()}`);
  console.log(colors.cyan + '═══════════════════════════════════════════════════════════════' + colors.reset);
  console.log('');
}

function getPreviousMetrics() {
  if (!fs.existsSync(METRICS_FILE)) {
    return null;
  }
  
  const content = fs.readFileSync(METRICS_FILE, 'utf-8');
  const lines = content.trim().split('\n');
  
  if (lines.length < 2) {
    return null;
  }
  
  const lastLine = lines[lines.length - 1];
  const values = lastLine.split(',');
  
  return {
    date: values[0],
    stars: parseInt(values[1]) || 0,
    forks: parseInt(values[2]) || 0,
    downloads: parseInt(values[6]) || 0,
  };
}

function calculateGrowth(current, previous) {
  if (!previous || previous === 0) return { change: 0, percent: 0 };
  const change = current - previous;
  const percent = ((change / previous) * 100).toFixed(1);
  return { change, percent };
}

async function main() {
  console.log(`${colors.cyan}Guardiant Metrics Collector v1.0${colors.reset}`);
  console.log(`${colors.gray}Collecting metrics from GitHub and NPM...${colors.reset}\n`);
  
  // Fetch stats in parallel
  const [github, npm] = await Promise.all([
    getGitHubStats(),
    getNPMStats(),
  ]);
  
  // Ensure data directory and CSV exist
  ensureDataDirectory();
  initializeCSV();
  
  // Get previous metrics for growth calculation
  const previous = getPreviousMetrics();
  
  // Append to CSV
  appendToCSV({ github, npm });
  
  // Display metrics
  displayMetrics(github, npm);
  
  // Show growth if we have previous data
  if (previous && github) {
    const starGrowth = calculateGrowth(github.stars, previous.stars);
    const forkGrowth = calculateGrowth(github.forks, previous.forks);
    const downloadGrowth = calculateGrowth(npm?.downloadsMonth || 0, previous.downloads);
    
    console.log(colors.yellow + 'Growth Since Last Collection:' + colors.reset);
    console.log(`  Stars:    ${starGrowth.change >= 0 ? colors.green : colors.red}${starGrowth.change >= 0 ? '+' : ''}${starGrowth.change} (${starGrowth.percent}%)${colors.reset}`);
    console.log(`  Forks:    ${forkGrowth.change >= 0 ? colors.green : colors.red}${forkGrowth.change >= 0 ? '+' : ''}${forkGrowth.change} (${forkGrowth.percent}%)${colors.reset}`);
    console.log(`  Downloads: ${downloadGrowth.change >= 0 ? colors.green : colors.red}${downloadGrowth.change >= 0 ? '+' : ''}${downloadGrowth.change} (${downloadGrowth.percent}%)${colors.reset}`);
    console.log('');
  }
  
  // Return data for programmatic use
  return { github, npm, timestamp: new Date().toISOString() };
}

// Run if called directly
if (require.main === module) {
  main()
    .then(() => {
      console.log(`${colors.green}Metrics collection complete!${colors.reset}`);
      process.exit(0);
    })
    .catch((error) => {
      console.error(`${colors.red}Error:${colors.reset}`, error);
      process.exit(1);
    });
}

module.exports = { getGitHubStats, getNPMStats, main };
