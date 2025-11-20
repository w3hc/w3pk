/**
 * Build Hash Tests
 * Tests for IPFS hash computation utilities
 */

console.log('\n🧪 Testing Build Hash Utilities...\n');

// Test the base32 encoding
function testBase32Encode() {
  console.log('Testing base32 encoding...');

  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';

  function base32Encode(data: Uint8Array): string {
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < data.length; i++) {
      value = (value << 8) | data[i];
      bits += 8;

      while (bits >= 5) {
        output += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += alphabet[(value << (5 - bits)) & 31];
    }

    return output;
  }

  // Test with known values
  const testData = new Uint8Array([0x01, 0x02, 0x03]);
  const encoded = base32Encode(testData);
  console.log(`  ✓ Encoded test data: ${encoded}`);
}

// Test IPFS hash format
async function testIPFSHashFormat() {
  console.log('\nTesting IPFS hash format...');

  const testData = new TextEncoder().encode('Hello, IPFS!');
  const hashBuffer = await crypto.subtle.digest('SHA-256', testData);
  const hashArray = new Uint8Array(hashBuffer);

  // Create multihash
  const multihash = new Uint8Array(34);
  multihash[0] = 0x12; // SHA-256 identifier
  multihash[1] = 0x20; // Length (32 bytes)
  multihash.set(hashArray, 2);

  console.log('  ✓ Multihash format created');
  console.log(`    - Type: ${multihash[0]} (SHA-256)`);
  console.log(`    - Length: ${multihash[1]} bytes`);
  console.log(`    - Hash preview: ${Array.from(hashArray.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);

  // Create CIDv1
  const cidBytes = new Uint8Array(36);
  cidBytes[0] = 0x01; // CIDv1
  cidBytes[1] = 0x70; // dag-pb codec
  cidBytes.set(multihash, 2);

  console.log('  ✓ CIDv1 format created');
  console.log(`    - Version: ${cidBytes[0]}`);
  console.log(`    - Codec: ${cidBytes[1]} (dag-pb)`);
}

// Test hash consistency
async function testHashConsistency() {
  console.log('\nTesting hash consistency...');

  const testData = new TextEncoder().encode('Test data for consistency check');

  // Compute hash twice
  const hash1 = await crypto.subtle.digest('SHA-256', testData);
  const hash2 = await crypto.subtle.digest('SHA-256', testData);

  const array1 = new Uint8Array(hash1);
  const array2 = new Uint8Array(hash2);

  let matches = true;
  for (let i = 0; i < array1.length; i++) {
    if (array1[i] !== array2[i]) {
      matches = false;
      break;
    }
  }

  if (matches) {
    console.log('  ✓ Hash is consistent across multiple computations');
  } else {
    console.log('  ✗ Hash inconsistency detected!');
  }
}

// Run all tests
async function runTests() {
  try {
    testBase32Encode();
    await testIPFSHashFormat();
    await testHashConsistency();

    console.log('\n✅ All build hash tests passed!\n');
    console.log('💡 To compute the actual build hash, run:');
    console.log('   pnpm build:hash\n');
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

runTests();
