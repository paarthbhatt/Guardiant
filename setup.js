#!/usr/bin/env node

/**
 * Guardiant Quick Setup Script
 * 
 * Helps users install and configure Guardiant with interactive prompts
 * 
 * Usage:
 *   node setup.js
 *   # or
 *   npm run setup
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const COLORS = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

function log(message, color = '') {
  console.log(`${color}${message}${COLORS.reset}`);
}

function logSuccess(message) {
  log(`✅ ${message}`, COLORS.green);
}

function logWarn(message) {
  log(`⚠️  ${message}`, COLORS.yellow);
}

function logError(message) {
  log(`❌ ${message}`, COLORS.red);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, COLORS.cyan);
}

 function logHeader(message) {
  log('\n' + '═'.repeat(60), COLORS.cyan);
  log(message, COLORS.bright);
  log('═'.repeat(60) + '\n', COLORS.cyan);
}

function checkNodeVersion() {
  try {
    const version = process.version;
    const major = parseInt(version.slice(1).split('.')[0], 10);
    
    if (major >= 20) {
      logSuccess(`Node.js ${version} is installed (required: ≥20)`);
      return true;
    } else {
      logError(`Node.js ${version} is too old. Required: ≥20`);
      return false;
    }
  } catch {
    logError('Node.js not found. Please install Node.js ≥20 from https://nodejs.org/');
    return false;
  }
}

function checkPnpm() {
  try {
    const version = execSync('pnpm --version', { encoding: 'utf-8' }).trim();
    logSuccess(`pnpm ${version} is installed`);
    return true;
  } catch {
    logWarn('pnpm not found. Will attempt to install or use npm...');
    return false;
  }
}

function installPnpm() {
  try {
    logInfo('Installing pnpm globally...');
    execSync('npm install -g pnpm', { stdio: 'inherit' });
    logSuccess('pnpm installed successfully');
    return true;
  } catch (error) {
    logError('Failed to install pnpm automatically');
    logInfo('Please install manually: npm install -g pnpm');
    return false;
  }
}

function detectOS() {
  const platform = process.platform;
  if (platform === 'win32') return 'Windows';
  if (platform === 'darwin') return 'macOS';
  if (platform === 'linux') return 'Linux';
  return platform;
}

function checkSqliteOnWindows() {
  if (process.platform !== 'win32') return true;

  logInfo('Windows detected. Checking SQLite dependency...');
  
  try {
    // Try to import better-sqlite3
    require('better-sqlite3');
    logSuccess('better-sqlite3 is available');
    return true;
  } catch {
    logWarn('better-sqlite3 not available (missing Visual Studio Build Tools)');
    logInfo('Guardiant will work in limited mode without database persistence');
    logInfo('For full functionality, choose one:');
    log('  1. Install Visual Studio Build Tools (https://aka.ms/vcpython)', COLORS.yellow);
    log('  2. Use WSL2 (recommended) - wsl --install', COLORS.yellow);
    return false;
  }
}

function createEnvFile() {
  const envPath = path.join(process.cwd(), '.env');
  
  if (fs.existsSync(envPath)) {
    logWarn('.env file already exists. Skipping...');
    return true;
  }

  const envExample = path.join(process.cwd(), '.env.example');
  if (!fs.existsSync(envExample)) {
    logError('.env.example not found. Cannot create .env file');
    return false;
  }

  fs.copyFileSync(envExample, envPath);
  logSuccess('.env file created from .env.example');
  logInfo('Please edit .env and add your LLM API key (ANTHROPIC_API_KEY, OPENROUTER_API_KEY, or GOOGLE_API_KEY)');
  return true;
}

function promptApiKey() {
  const apiKey = process.env.ANTHROPIC_API_KEY || process.env.OPENROUTER_API_KEY || process.env.GOOGLE_API_KEY;
  
  if (apiKey) {
    logSuccess('API key found in environment variables');
    return true;
  }

  logWarn('No LLM API key found in environment');
  logInfo('Guardiant requires at least one of:');
  log('  • ANTHROPIC_API_KEY (recommended)', COLORS.yellow);
  log('  • OPENROUTER_API_KEY', COLORS.yellow);
  log('  • GOOGLE_API_KEY', COLORS.yellow);

  const response = prompt('Would you like to add an API key now? (y/n): ');
  if (response.toLowerCase() === 'y') {
    logInfo('\nGet your API key from one of these providers:');
    log('  Anthropic: https://console.anthropic.com', COLORS.cyan);
    log('  OpenRouter: https://openrouter.ai', COLORS.cyan);
    log('  Google AI Studio: https://aistudio.google.com', COLORS.cyan);
    log('\n');
    
    const key = prompt('Enter your API key: ');
    if (key && key.trim()) {
      // Append to .env file
      const envPath = path.join(process.cwd(), '.env');
      const envContent = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf-8') : '';
      
      if (!envContent.includes('ANTHROPIC_API_KEY')) {
        fs.appendFileSync(envPath, `\nANTHROPIC_API_KEY=${key.trim()}\n`);
        logSuccess('API key added to .env file');
      }
      return true;
    }
  }

  logWarn('Skipping API key setup. You can configure it later with:');
  log('  guardiant config set anthropicApiKey YOUR_KEY', COLORS.gray);
  return false;
}

function prompt(question) {
  console.log(`${COLORS.yellow}${question}${COLORS.reset} `);
  const stdin = process.stdin;
  stdin.setRawMode(false);
  stdin.resume();
  stdin.setEncoding('utf-8');

  return new Promise((resolve) => {
    stdin.once('data', (data) => {
      resolve(data.trim());
    });
  });
}

async function main() {
  logHeader('🛡️  GUARDIANT SETUP WIZARD');
  
  logInfo('This wizard will help you install and configure Guardiant');
  log('Detected OS:', detectOS());
  log('');

  // Step 1: Check Node.js
  logHeader('📦 Step 1/5: Checking Node.js installation');
  if (!checkNodeVersion()) {
    logError('Node.js ≥20 is required. Please install it first.');
    process.exit(1);
  }

  // Step 2: Check pnpm
  logHeader('📦 Step 2/5: Checking pnpm');
  let hasPnpm = checkPnpm();
  if (!hasPnpm) {
    const installPnpmChoice = await prompt('Install pnpm now? (y/n): ');
    if (installPnpmChoice.toLowerCase() === 'y') {
      hasPnpm = installPnpm();
    } else {
      logWarn('You can use npm instead, but pnpm is recommended');
    }
  }

  // Step 3: Install dependencies
  logHeader('📦 Step 3/5: Installing dependencies');
  logInfo('This may take a few minutes...');
  
  try {
    if (hasPnpm) {
      execSync('pnpm install', { stdio: 'inherit' });
    } else {
      execSync('npm install', { stdio: 'inherit' });
    }
    logSuccess('Dependencies installed successfully');
  } catch (error) {
    logError('Failed to install dependencies');
    logInfo('Try running manually: pnpm install');
    process.exit(1);
  }

  // Step 4: Create .env file
  logHeader('⚙️  Step 4/5: Environment configuration');
  createEnvFile();

  // Step 5: Check SQLite/WSL on Windows
  if (process.platform === 'win32') {
    logHeader('🪟 Step 5/5: Windows-specific setup');
    checkSqliteOnWindows();
  } else {
    logHeader('✅ Step 5/5: Final setup');
    logSuccess('All systems ready!');
  }

  // Build
  log('');
  logInfo('Building project...');
  try {
    execSync('pnpm build', { stdio: 'inherit' });
    logSuccess('Build completed!');
  } catch (error) {
    logError('Build failed. Please check the error messages above.');
    process.exit(1);
  }

  // Summary
  logHeader('🎉 Setup Complete!');
  logSuccess('Guardiant has been installed successfully');
  log('');
  logInfo('Next steps:');
  log('  1. Add your LLM API key to .env file (if not done already)', COLORS.yellow);
  log('  2. Run your first scan:', COLORS.yellow);
  log('     guardiant scan https://example.com', COLORS.gray);
  log('');
  logInfo('Learn more:');
  log('  • Documentation: https://github.com/paarthbhatt/Guardiant', COLORS.cyan);
  log('  • CLI help: guardiant --help', COLORS.cyan);
  log('  • Troubleshooting: See README.md', COLORS.cyan);
  log('');
  log('🚀 Happy scanning!', COLORS.green);
  log('');
}

main().catch((error) => {
  logError('Setup failed: ' + error.message);
  process.exit(1);
});
