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
    const score = status.securityScore.total;
    const level = status.securityScore.level;

    if (methods.length === 0) {
      return `
❌ WALLET CANNOT BE RECOVERED

Scenario: ${scenario.description}
Current Security Score: ${score}/70 (${level})

Unfortunately, you have no recovery options for this scenario.

This is why backup is critical!

IMMEDIATE ACTION REQUIRED:
-------------------------

To prevent permanent loss, set up both of these:

1. Encrypted Backup (+20 pts)
   - Takes 2 minutes
   - Works anywhere
   - Requires password
   [Create backup now]

2. Verify Your Backup (+10 pts)
   - Test restore process
   - Proves backup works
   - Takes 5 minutes
   [Test backup now]

Target: Reach at least 21/70 for basic protection!

---

Don't wait until it's too late!
`;
    }

    let note = `✅ YOU CAN RECOVER!\n\nScenario: ${scenario.description}\n`;
    note += `Security Score: ${score}/70 (${level})\n\n`;

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

    // Add score-based recommendations
    note += `\nSECURITY RECOMMENDATIONS:\n`;

    if (score <= 20) {
      note += `⚠️  Your score is 20/70 or below.\n`;
      note += `   Add more backups to improve protection:\n\n`;

      if (!status.recoveryPhrase.encryptedBackups.length) {
        note += `   📥 Create encrypted backup → +20 pts\n`;
      }

      if (!status.recoveryPhrase.verified) {
        note += `   ✅ Verify your backup → +10 pts\n`;
      }
    } else if (score <= 40) {
      note += `🟡 Good start! Score: ${score}/70\n\n`;

      if (!status.recoveryPhrase.verified) {
        note += `   ✅ Verify your backup → +10 pts\n`;
      }

      note += `\n   Target: Reach 41+ for "secured" status!\n`;
    } else if (score <= 60) {
      note += `🟢 Great! Score: ${score}/70\n\n`;

      if (status.passkeySync.deviceCount === 1) {
        note += `   📱 Sync passkey to another device → +10 pts\n`;
      }

      note += `\n   You're close to "fort-knox" status!\n`;
    } else {
      note += `🏆 Excellent! Score: ${score}/70\n`;
      note += `   Your wallet is extremely well-protected!\n`;
      note += `   You can survive almost any disaster scenario.\n`;
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
    securityScore: number;
    feedback: string;
  }> {
    const scenarios = this.getScenarios();
    const results: SimulationResult[] = [];

    for (const scenario of scenarios) {
      const result = await this.simulateScenario(scenario, currentStatus);
      results.push(result);
    }

    // Calculate recovery score
    const successCount = results.filter((r) => r.success).length;
    const overallScore = (successCount / scenarios.length) * 100;

    // Get security score
    const securityScore = currentStatus.securityScore.total;
    const securityLevel = currentStatus.securityScore.level;

    let feedback = '';

    // Combined feedback based on both recovery and security scores
    feedback += `RECOVERY TEST RESULTS\n`;
    feedback += `${'='.repeat(50)}\n\n`;

    if (overallScore === 100) {
      feedback += `🏆 PERFECT! You can recover in ALL scenarios.\n`;
    } else if (overallScore >= 75) {
      feedback += `🟢 GREAT! You can recover in ${successCount}/${scenarios.length} scenarios.\n`;
    } else if (overallScore >= 50) {
      feedback += `🟡 GOOD! You can recover in ${successCount}/${scenarios.length} scenarios.\n`;
    } else {
      feedback += `⚠️  AT RISK! You can only recover in ${successCount}/${scenarios.length} scenarios.\n`;
    }

    feedback += `\nSECURITY SCORE: ${securityScore}/70 (${securityLevel})\n`;
    feedback += `${'='.repeat(50)}\n\n`;

    // Score breakdown
    feedback += `SCORE BREAKDOWN:\n\n`;
    const breakdown = currentStatus.securityScore.breakdown;

    feedback += `🔑 Passkey Active: ${breakdown.passkeyActive}/20\n`;
    feedback += `📱 Multi-Device Sync: ${breakdown.passkeyMultiDevice}/10\n`;
    feedback += `💾 Encrypted Backup: ${breakdown.encryptedBackup}/20\n`;
    feedback += `✅ Backup Verified: ${breakdown.phraseVerified}/20\n\n`;

    // Recommendations based on security score
    feedback += `NEXT STEPS:\n`;
    feedback += `${'='.repeat(50)}\n\n`;

    if (securityScore > 60) {
      feedback += `🏆 Excellent security posture!\n`;
      feedback += `Your wallet is extremely well-protected.\n\n`;

      if (securityScore < 70) {
        feedback += `To reach perfect 70/70:\n`;
        if (breakdown.passkeyMultiDevice === 0) {
          feedback += `  • Sync passkey to another device (+10 pts)\n`;
        }
        if (breakdown.phraseVerified < 20) {
          feedback += `  • Verify your backup multiple times (+${20 - breakdown.phraseVerified} pts)\n`;
        }
      }
    } else if (securityScore > 20) {
      feedback += `${currentStatus.securityScore.nextMilestone}\n\n`;
      feedback += `Recommended actions:\n`;

      if (breakdown.encryptedBackup === 0) {
        feedback += `  1. Create encrypted backup (+20 pts)\n`;
      }
      if (breakdown.phraseVerified === 0) {
        feedback += `  2. Test your backup (+10 pts)\n`;
      }
    } else {
      feedback += `⚠️  URGENT: Your wallet security is at risk!\n\n`;
      feedback += `Critical actions needed:\n`;
      feedback += `  1. Create encrypted backup NOW (+20 pts)\n`;
      feedback += `  2. Test the backup immediately (+10 pts)\n\n`;
      feedback += `Target: Reach at least 21/70 for basic protection.\n`;
    }

    return {
      scenarios: results,
      overallScore,
      securityScore,
      feedback,
    };
  }
}
