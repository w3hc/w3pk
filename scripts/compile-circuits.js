#!/usr/bin/env node

/**
 * Circuit Compilation Script
 * Compiles Circom circuits to WASM and generates proving keys
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const CIRCUITS_DIR = path.join(__dirname, '../src/zk/circuits');
const OUTPUT_DIR = path.join(__dirname, '../src/zk/templates');
const WASM_DIR = path.join(OUTPUT_DIR, 'wasm');
const ZKEY_DIR = path.join(OUTPUT_DIR, 'zkeys');

const CIRCUITS = [
  'membership',
  'threshold',
  'range',
  'ownership'
];

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  blue: '\x1b[34m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function ensureDirectories() {
  [OUTPUT_DIR, WASM_DIR, ZKEY_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      log(`✓ Created directory: ${dir}`, 'green');
    }
  });
}

function checkDependencies() {
  try {
    // Load Rust environment and update PATH
    const homeDir = require('os').homedir();
    const cargoPath = `${homeDir}/.cargo/bin`;
    process.env.PATH = `${cargoPath}:${process.env.PATH}`;
    
    execSync('circom --version', { stdio: 'ignore' });
    log('✓ circom found', 'green');
  } catch (error) {
    log('✗ circom not found. Install circom 2.x from: https://github.com/iden3/circom', 'red');
    log('  Run: cargo install --git https://github.com/iden3/circom circom', 'yellow');
    process.exit(1);
  }

  try {
    // Check which command exists
    try {
      execSync('which snarkjs', { stdio: 'ignore' });
      log('✓ snarkjs found (global)', 'green');
    } catch {
      try {
        // Check if local snarkjs exists
        const fs = require('fs');
        const path = require('path');
        const localSnarkjs = path.join(process.cwd(), 'node_modules', '.bin', 'snarkjs');
        if (fs.existsSync(localSnarkjs)) {
          log('✓ snarkjs found (local)', 'green');
        } else {
          throw new Error('snarkjs not found');
        }
      } catch {
        throw new Error('snarkjs not found');
      }
    }
  } catch (error) {
    log('✗ snarkjs not found. Install with: npm install -g snarkjs or npm install snarkjs', 'red');
    process.exit(1);
  }
}

function compileCircuit(name) {
  log(`\nCompiling ${name} circuit...`, 'blue');
  
  const circuitPath = path.join(CIRCUITS_DIR, `${name}.circom`);
  const outputPath = OUTPUT_DIR; // Use the templates directory as base

  try {
    // Compile circuit with library path (PATH already updated in checkDependencies)
    execSync(
      `circom ${circuitPath} --r1cs --wasm --sym -o ${outputPath} -l node_modules`,
      { stdio: 'inherit' }
    );
    log(`✓ Compiled ${name}.circom`, 'green');

    // Move files to correct locations
    const r1csPath = path.join(outputPath, `${name}.r1cs`);
    const symPath = path.join(outputPath, `${name}.sym`);
    const wasmJsDir = path.join(outputPath, `${name}_js`);
    const wasmSrcPath = path.join(wasmJsDir, `${name}.wasm`);
    const wasmDstPath = path.join(WASM_DIR, `${name}.wasm`);
    
    if (fs.existsSync(wasmSrcPath)) {
      fs.copyFileSync(wasmSrcPath, wasmDstPath);
      log(`✓ Copied ${name}.wasm to wasm directory`, 'green');
    }

    return true;
  } catch (error) {
    log(`✗ Failed to compile ${name}:`, 'red');
    console.error(error.message);
    return false;
  }
}

function generateProvingKey(name) {
  log(`\nGenerating proving key for ${name}...`, 'blue');

  const r1csPath = path.join(WASM_DIR, name, `${name}.r1cs`);
  const zkeyPath = path.join(ZKEY_DIR, `${name}_final.zkey`);
  const vkeyPath = path.join(ZKEY_DIR, `${name}_verification_key.json`);

  // Check if powers of tau file exists
  const ptauPath = path.join(__dirname, 'powersOfTau28_hez_final_12.ptau');
  
  if (!fs.existsSync(ptauPath)) {
    log('Powers of Tau file not found. Downloading...', 'yellow');
    log('This is a one-time operation and may take a few minutes.', 'yellow');
    
    try {
      // Skip proving key generation for now - it's optional for development
      log('⚠️ Skipping Powers of Tau download for now', 'yellow');
      log('  For production, download from: https://github.com/iden3/snarkjs#7-prepare-phase-2', 'yellow');
      return false; // Skip this step
    } catch (error) {
      return false;
    }
  }

  try {
    // Generate proving key
    log('Running Groth16 setup (this may take a while)...', 'yellow');
    
    // Try global snarkjs first, then npx
    try {
      execSync(
        `snarkjs groth16 setup ${r1csPath} ${ptauPath} ${zkeyPath}`,
        { stdio: 'inherit' }
      );
    } catch {
      execSync(
        `npx snarkjs groth16 setup ${r1csPath} ${ptauPath} ${zkeyPath}`,
        { stdio: 'inherit' }
      );
    }
    log(`✓ Generated ${name}_final.zkey`, 'green');

    // Export verification key
    try {
      execSync(
        `snarkjs zkey export verificationkey ${zkeyPath} ${vkeyPath}`,
        { stdio: 'inherit' }
      );
    } catch {
      execSync(
        `npx snarkjs zkey export verificationkey ${zkeyPath} ${vkeyPath}`,
        { stdio: 'inherit' }
      );
    }
    log(`✓ Exported verification key`, 'green');

    return true;
  } catch (error) {
    log(`✗ Failed to generate proving key for ${name}:`, 'red');
    console.error(error.message);
    return false;
  }
}

function createArtifactIndex() {
  log('\nCreating artifact index...', 'blue');

  const artifacts = {};
  
  CIRCUITS.forEach(name => {
    const wasmPath = path.join(WASM_DIR, `${name}.wasm`);
    const zkeyPath = path.join(ZKEY_DIR, `${name}_final.zkey`);
    const vkeyPath = path.join(ZKEY_DIR, `${name}_verification_key.json`);

    if (fs.existsSync(vkeyPath)) {
      const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
      
      artifacts[name] = {
        wasmPath: wasmPath.replace(path.join(__dirname, '..'), '.'),
        zkeyPath: zkeyPath.replace(path.join(__dirname, '..'), '.'),
        verificationKey: vkey
      };
    }
  });

  const indexPath = path.join(OUTPUT_DIR, 'artifacts.json');
  fs.writeFileSync(indexPath, JSON.stringify(artifacts, null, 2));
  log(`✓ Created artifacts.json`, 'green');
}

function main() {
  log('=== w3pk Circuit Compilation ===', 'blue');
  
  checkDependencies();
  ensureDirectories();

  let successCount = 0;

  // Compile all circuits
  CIRCUITS.forEach(name => {
    if (compileCircuit(name)) {
      successCount++;
    }
  });

  if (successCount === 0) {
    log('\n✗ No circuits compiled successfully', 'red');
    process.exit(1);
  }

  // Generate proving keys
  log('\n=== Generating Proving Keys ===', 'blue');
  log('NOTE: This step is optional for development.', 'yellow');
  log('For production, you should run a trusted setup ceremony.', 'yellow');
  log('Press Ctrl+C to skip, or wait to continue...', 'yellow');

  setTimeout(() => {
    CIRCUITS.forEach(name => {
      generateProvingKey(name);
    });

    createArtifactIndex();

    log('\n=== Compilation Complete ===', 'green');
    log(`✓ Compiled ${successCount}/${CIRCUITS.length} circuits`, 'green');
    log('\nCircuit artifacts are ready in src/zk/templates/', 'blue');
  }, 3000);
}

main();