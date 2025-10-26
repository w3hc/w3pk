/**
 * Recovery Scenario Simulator
 * Educational tool to help users understand recovery options
 */

import type { BackupStatus } from '../backup/types';
import type {
  RecoveryScenario,
  SimulationResult,
  RecoveryMethod,
} from '../backup/types';

export class RecoverySimulator {
  /**
   * Predefined recovery scenarios
   */
  getScenarios(): RecoveryScenario[] {
    return [
      {
        type: 'lost-device',
        description: 'Your phone fell in the ocean',
      },
      {
        type: 'lost-phrase',
        description: 'Your paper backup burned in a fire',
      },
      {
        type: 'lost-both',
        description: 'Phone stolen AND forgot recovery phrase',
      },
      {
        type: 'switch-platform',
        description: 'Switching from iPhone to Android',
      },
    ];
  }

  /**
   * Simulate a recovery scenario
   */
  async simulateScenario(
    scenario: RecoveryScenario,
    currentStatus: BackupStatus
  ): Promise<SimulationResult> {
    const methods: RecoveryMethod[] = [];

    switch (scenario.type) {
      case 'lost-device':
        // Check passkey sync
        if (
          currentStatus.passkeySync.enabled &&
          currentStatus.passkeySync.deviceCount > 1
        ) {
          methods.push({
            method: `Passkey Sync (${currentStatus.passkeySync.platform})`,
            success: true,
            time: '5 minutes',
            requirements: [
              'Sign in to cloud account on new device',
              'Authenticate with biometric/PIN',
            ],
          });
        }

        // Check encrypted backups
        if (currentStatus.recoveryPhrase.encryptedBackups.length > 0) {
          currentStatus.recoveryPhrase.encryptedBackups.forEach((backup) => {
            methods.push({
              method: `Encrypted ${backup.method.toUpperCase()} Backup`,
              success: true,
              time: '2 minutes',
              requirements: ['Backup file/QR code', 'Backup password'],
            });
          });
        }

        // Check social recovery
        if (currentStatus.socialRecovery?.enabled) {
          methods.push({
            method: 'Social Recovery',
            success: true,
            time: '24 hours',
            requirements: [
              `Contact ${currentStatus.socialRecovery.threshold} guardians`,
              'Collect shares from guardians',
              'Verify identity with each guardian',
            ],
          });
        }
        break;

      case 'lost-phrase':
        // Passkey still works on current device
        if (currentStatus.passkeySync.enabled) {
          methods.push({
            method: 'Passkey (current device)',
            success: true,
            time: 'Instant',
            requirements: ['Access to current device', 'Biometric/PIN authentication'],
          });
        }

        // Passkey sync to other devices
        if (currentStatus.passkeySync.deviceCount > 1) {
          methods.push({
            method: 'Passkey Sync',
            success: true,
            time: '5 minutes',
            requirements: ['Any synced device', 'Biometric authentication'],
          });
        }

        // Encrypted backups still work
        if (currentStatus.recoveryPhrase.encryptedBackups.length > 0) {
          methods.push({
            method: 'Encrypted Backup',
            success: true,
            time: '2 minutes',
            requirements: ['Backup file', 'Password'],
          });
        }

        // Social recovery
        if (currentStatus.socialRecovery?.enabled) {
          methods.push({
            method: 'Social Recovery',
            success: true,
            time: '24 hours',
            requirements: [`${currentStatus.socialRecovery.threshold} guardian shares`],
          });
        }
        break;

      case 'lost-both':
        // Only passkey sync can help
        if (currentStatus.passkeySync.deviceCount > 1) {
          methods.push({
            method: 'Passkey Sync',
            success: true,
            time: '5 minutes',
            requirements: [
              'Cloud account access',
              'New device',
              'Biometric setup',
            ],
          });
        }

        // Social recovery is the safety net
        if (currentStatus.socialRecovery?.enabled) {
          methods.push({
            method: 'Social Recovery',
            success: true,
            time: '24 hours',
            requirements: [
              `${currentStatus.socialRecovery.threshold} guardian shares`,
              'Identity verification with guardians',
            ],
          });
        }
        break;

      case 'switch-platform':
        // Passkey sync doesn't work cross-platform
        // Only universal backups work
        if (currentStatus.recoveryPhrase.encryptedBackups.length > 0) {
          methods.push({
            method: 'Encrypted Backup',
            success: true,
            time: '2 minutes',
            requirements: ['Backup file', 'Password'],
          });
        }

        if (currentStatus.socialRecovery?.enabled) {
          methods.push({
            method: 'Social Recovery',
            success: true,
            time: '24 hours',
            requirements: [`${currentStatus.socialRecovery.threshold} guardian shares`],
          });
        }
        break;
    }

    const success = methods.length > 0;

    let educationalNote = this.getEducationalNote(
      scenario,
      methods,
      currentStatus
    );

    return {
      scenario,
      success,
      availableMethods: methods,
      timeEstimate: success ? this.estimateFastestRecovery(methods) : 'Cannot recover',
      educationalNote,
    };
  }

  /**
   * Estimate fastest recovery time
   */
  private estimateFastestRecovery(methods: RecoveryMethod[]): string {
    const times = methods.map((m) => m.time.toLowerCase());

    if (times.some((t) => t.includes('instant'))) return 'Instant';
    if (times.some((t) => t.includes('minute'))) {
      const minutes = times
        .filter((t) => t.includes('minute'))
        .map((t) => parseInt(t));
      return `${Math.min(...minutes)} minutes`;
    }
    if (times.some((t) => t.includes('hour'))) return '24 hours';

    return 'Unknown';
  }

  /**
   * Get educational note for scenario
   */
  private getEducationalNote(
    scenario: RecoveryScenario,
    methods: RecoveryMethod[],
    status: BackupStatus
  ): string {
    if (methods.length === 0) {
      return `
❌ WALLET CANNOT BE RECOVERED

Scenario: ${scenario.description}

Unfortunately, you have no recovery options for this scenario.

This is why backup is critical!

IMMEDIATE ACTION REQUIRED:
-------------------------

To prevent permanent loss, set up AT LEAST TWO of these:

1. Encrypted Backup
   - Takes 2 minutes
   - Works anywhere
   - Requires password
   [Create backup now]

2. Social Recovery
   - Takes 30 minutes setup
   - Most secure
   - Requires 3-5 trusted friends
   [Set up guardians]

3. Verify Passkey Sync
   - Check if enabled
   - Test on another device
   - Platform-specific
   [Check sync status]

---

Don't wait until it's too late!
`;
    }

    let note = `✅ YOU CAN RECOVER!\n\nScenario: ${scenario.description}\n\n`;

    note += `Available recovery methods (${methods.length}):\n\n`;

    methods.forEach((method, index) => {
      note += `${index + 1}. ${method.method}\n`;
      note += `   ⏱  Time: ~${method.time}\n`;
      note += `   Requirements:\n`;
      method.requirements.forEach((req) => {
        note += `   - ${req}\n`;
      });
      note += `\n`;
    });

    // Add recommendations
    note += `\nRECOMMENDATIONS:\n`;

    if (methods.length === 1) {
      note += `⚠️  You only have ONE recovery method.\n`;
      note += `   Add more backups for better security:\n`;

      if (!status.recoveryPhrase.encryptedBackups.length) {
        note += `   - Create encrypted backup\n`;
      }

      if (!status.socialRecovery?.enabled) {
        note += `   - Set up social recovery\n`;
      }
    } else if (methods.length === 2) {
      note += `🟡 Good! You have ${methods.length} recovery methods.\n`;

      if (!status.socialRecovery?.enabled) {
        note += `   Consider adding social recovery for maximum security.\n`;
      }
    } else {
      note += `🟢 Excellent! You have ${methods.length} recovery methods.\n`;
      note += `   Your wallet is well-protected!\n`;
    }

    return note;
  }

  /**
   * Run interactive test
   */
  async runInteractiveTest(
    currentStatus: BackupStatus
  ): Promise<{
    scenarios: SimulationResult[];
    overallScore: number;
    feedback: string;
  }> {
    const scenarios = this.getScenarios();
    const results: SimulationResult[] = [];

    for (const scenario of scenarios) {
      const result = await this.simulateScenario(scenario, currentStatus);
      results.push(result);
    }

    // Calculate score
    const successCount = results.filter((r) => r.success).length;
    const overallScore = (successCount / scenarios.length) * 100;

    let feedback = '';

    if (overallScore === 100) {
      feedback = `🏆 PERFECT SCORE!\n\nYou can recover in ALL scenarios.\nYour wallet is extremely well-protected!`;
    } else if (overallScore >= 75) {
      feedback = `🟢 GREAT JOB!\n\nYou can recover in ${successCount}/${scenarios.length} scenarios.\nConsider adding more backup methods for complete coverage.`;
    } else if (overallScore >= 50) {
      feedback = `🟡 GOOD START!\n\nYou can recover in ${successCount}/${scenarios.length} scenarios.\nAdd more backup methods to improve security.`;
    } else {
      feedback = `⚠️  AT RISK!\n\nYou can only recover in ${successCount}/${scenarios.length} scenarios.\nUrgently add backup methods to protect your wallet!`;
    }

    return {
      scenarios: results,
      overallScore,
      feedback,
    };
  }
}
