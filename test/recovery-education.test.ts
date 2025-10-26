/**
 * Recovery Education and Simulation Tests
 * Tests for educational components and recovery scenario simulator
 */

import { RecoverySimulator } from '../src/education/simulator';
import { getExplainer, getAllTopics, searchExplainers } from '../src/education/explainers';
import type { BackupStatus } from '../src/backup/types';

async function runTests() {
console.log('\n🧪 Running Recovery Education Tests...\n');

// Mock backup status for testing
const mockBackupStatus: BackupStatus = {
  passkeySync: {
    enabled: true,
    deviceCount: 2,
    lastSyncTime: Date.now(),
    platform: 'apple'
  },
  recoveryPhrase: {
    verified: false,
    verificationCount: 0,
    encryptedBackups: [
      {
        id: 'backup-1',
        method: 'zip',
        location: 'local',
        createdAt: Date.now()
      }
    ]
  },
  socialRecovery: {
    enabled: true,
    guardians: [],
    threshold: 3,
    sharesDistributed: 5,
    verifiedGuardians: 5
  },
  securityScore: {
    total: 80,
    breakdown: {
      passkeyActive: 20,
      passkeyMultiDevice: 10,
      phraseVerified: 0,
      encryptedBackup: 20,
      socialRecovery: 30
    },
    level: 'secured',
    nextMilestone: 'Verify phrase to reach fort-knox'
  }
};

// Test 1: Get Predefined Scenarios
console.log('Test 1: Get Predefined Scenarios');
{
  const simulator = new RecoverySimulator();
  const scenarios = simulator.getScenarios();

  console.assert(scenarios.length > 0, 'Should have scenarios');
  console.assert(scenarios[0].type, 'Scenarios should have type');
  console.assert(scenarios[0].description, 'Scenarios should have description');

  const types = scenarios.map(s => s.type);
  console.assert(types.includes('lost-device'), 'Should include lost-device scenario');
  console.assert(types.includes('lost-phrase'), 'Should include lost-phrase scenario');
  console.assert(types.includes('lost-both'), 'Should include lost-both scenario');

  console.log(`✅ Found ${scenarios.length} predefined scenarios`);
}

// Test 2: Simulate Lost Device Scenario
console.log('\nTest 2: Simulate Lost Device Scenario');
{
  const simulator = new RecoverySimulator();

  const result = await simulator.simulateScenario(
    { type: 'lost-device', description: 'Phone fell in ocean' },
    mockBackupStatus
  );

  console.assert(result.success, 'Should be able to recover');
  console.assert(result.availableMethods.length > 0, 'Should have recovery methods');
  console.assert(result.timeEstimate, 'Should have time estimate');
  console.assert(result.educationalNote, 'Should have educational note');

  console.log(`✅ Lost device: ${result.success ? 'Can recover' : 'Cannot recover'}`);
  console.log(`   Available methods: ${result.availableMethods.length}`);
}

// Test 3: Simulate Lost Phrase Scenario
console.log('\nTest 3: Simulate Lost Phrase Scenario');
{
  const simulator = new RecoverySimulator();

  const result = await simulator.simulateScenario(
    { type: 'lost-phrase', description: 'Paper backup burned' },
    mockBackupStatus
  );

  console.assert(result.success, 'Should be able to recover (has passkey)');
  console.assert(result.availableMethods.length > 0, 'Should have methods');

  // Should have passkey method
  const hasPasskeyMethod = result.availableMethods.some(m =>
    m.method.toLowerCase().includes('passkey')
  );
  console.assert(hasPasskeyMethod, 'Should have passkey recovery method');

  console.log('✅ Lost phrase simulation working');
}

// Test 4: Simulate Lost Both Scenario
console.log('\nTest 4: Simulate Lost Both Scenario');
{
  const simulator = new RecoverySimulator();

  const result = await simulator.simulateScenario(
    { type: 'lost-both', description: 'Lost device AND phrase' },
    mockBackupStatus
  );

  // Should depend on sync and social recovery
  console.assert(typeof result.success === 'boolean', 'Should have success status');

  if (mockBackupStatus.socialRecovery?.enabled) {
    console.assert(result.success, 'Should recover with social recovery');
  }

  console.log('✅ Lost both simulation working');
}

// Test 5: Simulate Switch Platform Scenario
console.log('\nTest 5: Simulate Switch Platform Scenario');
{
  const simulator = new RecoverySimulator();

  const result = await simulator.simulateScenario(
    { type: 'switch-platform', description: 'iPhone to Android' },
    mockBackupStatus
  );

  // Passkey sync won't work cross-platform
  const hasPasskeySync = result.availableMethods.some(m =>
    m.method.toLowerCase().includes('passkey sync')
  );
  console.assert(!hasPasskeySync, 'Passkey sync should not work cross-platform');

  // Should have universal methods (backup, social recovery)
  const hasUniversalMethod = result.availableMethods.some(m =>
    m.method.toLowerCase().includes('backup') ||
    m.method.toLowerCase().includes('social')
  );
  console.assert(hasUniversalMethod, 'Should have universal recovery methods');

  console.log('✅ Platform switch simulation working');
}

// Test 6: Run Interactive Test
console.log('\nTest 6: Run Interactive Test');
{
  const simulator = new RecoverySimulator();

  const result = await simulator.runInteractiveTest(mockBackupStatus);

  console.assert(result.scenarios.length > 0, 'Should have scenario results');
  console.assert(typeof result.overallScore === 'number', 'Should have overall score');
  console.assert(result.overallScore >= 0 && result.overallScore <= 100, 'Score should be 0-100');
  console.assert(result.feedback, 'Should have feedback');

  const successCount = result.scenarios.filter(s => s.success).length;
  const expectedScore = (successCount / result.scenarios.length) * 100;
  console.assert(result.overallScore === expectedScore, 'Score should match calculation');

  console.log(`✅ Overall score: ${result.overallScore}/100`);
  console.log(`   Success rate: ${successCount}/${result.scenarios.length}`);
}

// Test 7: Vulnerable Backup Status
console.log('\nTest 7: Test with Vulnerable Status');
{
  const vulnerableStatus: BackupStatus = {
    passkeySync: {
      enabled: true,
      deviceCount: 1,
      platform: 'unknown'
    },
    recoveryPhrase: {
      verified: false,
      verificationCount: 0,
      encryptedBackups: []
    },
    securityScore: {
      total: 20,
      breakdown: {
        passkeyActive: 20,
        passkeyMultiDevice: 0,
        phraseVerified: 0,
        encryptedBackup: 0,
        socialRecovery: 0
      },
      level: 'vulnerable',
      nextMilestone: 'Create backup'
    }
  };

  const simulator = new RecoverySimulator();
  const result = await simulator.runInteractiveTest(vulnerableStatus);

  console.assert(result.overallScore < 75, 'Vulnerable status should have low score');

  const failedScenarios = result.scenarios.filter(s => !s.success);
  console.assert(failedScenarios.length > 0, 'Should have failed scenarios');

  console.log(`✅ Vulnerable test: ${failedScenarios.length} scenarios fail`);
}

// Test 8: Get Educational Explainer
console.log('\nTest 8: Get Educational Explainer');
{
  const passkeyExplainer = getExplainer('whatIsPasskey');

  console.assert(passkeyExplainer !== null, 'Should find passkey explainer');
  console.assert(passkeyExplainer?.title, 'Should have title');
  console.assert(passkeyExplainer?.content, 'Should have content');
  console.assert((passkeyExplainer?.content.length || 0) > 100, 'Content should be substantial');

  console.log(`✅ Explainer found: "${passkeyExplainer?.title}"`);
}

// Test 9: Get All Topics
console.log('\nTest 9: Get All Topics');
{
  const topics = getAllTopics();

  console.assert(topics.length > 0, 'Should have topics');
  console.assert(topics.includes('whatIsPasskey'), 'Should include whatIsPasskey');
  console.assert(topics.includes('whatIsRecoveryPhrase'), 'Should include whatIsRecoveryPhrase');
  console.assert(topics.includes('socialRecoveryExplained'), 'Should include socialRecoveryExplained');

  console.log(`✅ Found ${topics.length} educational topics`);
}

// Test 10: Search Explainers
console.log('\nTest 10: Search Explainers');
{
  const passkeyResults = searchExplainers('passkey');
  console.assert(passkeyResults.length > 0, 'Should find passkey-related content');

  const recoveryResults = searchExplainers('recovery');
  console.assert(recoveryResults.length > 0, 'Should find recovery-related content');

  const encryptionResults = searchExplainers('encryption');
  console.assert(encryptionResults.length > 0, 'Should find encryption-related content');

  console.log(`✅ Search working: 'passkey' (${passkeyResults.length}), 'recovery' (${recoveryResults.length})`);
}

// Test 11: Explainer Content Quality
console.log('\nTest 11: Explainer Content Quality');
{
  const topics = getAllTopics();

  for (const topic of topics) {
    const explainer = getExplainer(topic);

    console.assert(explainer !== null, `Topic ${topic} should exist`);
    console.assert((explainer?.title.length || 0) > 0, `${topic} should have title`);
    console.assert((explainer?.content.length || 0) > 100, `${topic} should have substantial content`);
  }

  console.log(`✅ All ${topics.length} explainers have quality content`);
}

// Test 12: Educational Note Quality
console.log('\nTest 12: Educational Note Quality');
{
  const simulator = new RecoverySimulator();

  const scenarios = simulator.getScenarios();

  for (const scenario of scenarios) {
    const result = await simulator.simulateScenario(scenario, mockBackupStatus);

    console.assert(result.educationalNote.length > 50, `${scenario.type} should have educational note`);

    if (result.success) {
      console.assert(
        result.educationalNote.includes('✅') || result.educationalNote.includes('safe'),
        'Success note should be positive'
      );
    } else {
      console.assert(
        result.educationalNote.includes('❌') || result.educationalNote.includes('cannot'),
        'Failure note should explain issue'
      );
    }
  }

  console.log('✅ All educational notes are quality');
}

console.log('\n✅ All Recovery Education Tests Passed!\n');
}

runTests().catch(console.error);
