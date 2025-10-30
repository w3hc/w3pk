/**
 * Test Utilities
 * Shared utilities for consistent test execution and output formatting
 */

// Track test results
interface TestResult {
  name: string;
  passed: boolean;
  error?: Error;
}

const testResults: TestResult[] = [];
let currentTestSuite = '';

/**
 * Start a test suite with a formatted header
 */
export function startTestSuite(name: string): void {
  currentTestSuite = name;
  console.log(`\n${'='.repeat(50)}`);
  console.log(`🚀 ${name}`);
  console.log(`${'='.repeat(50)}\n`);
}

/**
 * End a test suite with a summary
 */
export function endTestSuite(): void {
  const passed = testResults.filter(r => r.passed).length;
  const failed = testResults.filter(r => !r.passed).length;

  console.log(`\n${'='.repeat(50)}`);
  if (failed === 0) {
    console.log(`✅ All tests passed! (${passed}/${testResults.length})`);
  } else {
    console.log(`❌ Some tests failed! (${passed}/${testResults.length} passed, ${failed} failed)`);
  }
  console.log(`${'='.repeat(50)}\n`);

  // Exit with error code if any tests failed
  if (failed > 0) {
    process.exit(1);
  }
}

/**
 * Log a test header
 */
export function startTest(name: string): void {
  console.log(`\nTest: ${name}`);
}

/**
 * Log a successful test result
 */
export function passTest(message?: string): void {
  if (message) {
    console.log(`  ✅ ${message}`);
  } else {
    console.log(`  ✅ Passed`);
  }
}

/**
 * Log a failed test result
 */
export function failTest(message: string): void {
  console.log(`  ❌ ${message}`);
}

/**
 * Log an info message
 */
export function logInfo(message: string): void {
  console.log(`  ℹ️  ${message}`);
}

/**
 * Log a warning message
 */
export function logWarning(message: string): void {
  console.log(`  ⚠️  ${message}`);
}

/**
 * Log a detail message
 */
export function logDetail(message: string): void {
  console.log(`  ${message}`);
}

/**
 * Run a test function with error handling
 */
export async function runTest(name: string, testFn: () => Promise<void> | void): Promise<void> {
  startTest(name);
  try {
    await testFn();
    testResults.push({ name, passed: true });
  } catch (error) {
    const err = error as Error;
    failTest(err.message);
    testResults.push({ name, passed: false, error: err });
  }
}

/**
 * Check if an optional dependency is available
 */
export function checkOptionalDependency(moduleName: string): boolean {
  try {
    require.resolve(moduleName);
    return true;
  } catch {
    return false;
  }
}

/**
 * Skip a test with a message
 */
export function skipTest(reason: string): void {
  logWarning(`Skipped: ${reason}`);
}

/**
 * Run a test suite with multiple tests
 */
export async function runTestSuite(
  suiteName: string,
  tests: Array<{ name: string; fn: () => Promise<void> | void }>
): Promise<void> {
  startTestSuite(suiteName);

  for (const test of tests) {
    await runTest(test.name, test.fn);
  }

  endTestSuite();
}

/**
 * Enhanced console.assert with better error messages
 */
export function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

/**
 * Assert equality with better error messages
 */
export function assertEqual<T>(actual: T, expected: T, message?: string): void {
  if (actual !== expected) {
    const msg = message || `Expected ${expected}, got ${actual}`;
    throw new Error(`Assertion failed: ${msg}`);
  }
}

/**
 * Assert that a value is truthy
 */
export function assertTruthy(value: unknown, message?: string): void {
  if (!value) {
    const msg = message || `Expected truthy value, got ${value}`;
    throw new Error(`Assertion failed: ${msg}`);
  }
}

/**
 * Assert that a value is falsy
 */
export function assertFalsy(value: unknown, message?: string): void {
  if (value) {
    const msg = message || `Expected falsy value, got ${value}`;
    throw new Error(`Assertion failed: ${msg}`);
  }
}

/**
 * Assert that a function throws an error
 */
export async function assertThrows(
  fn: () => Promise<void> | void,
  message?: string
): Promise<void> {
  let threw = false;
  try {
    await fn();
  } catch {
    threw = true;
  }
  if (!threw) {
    const msg = message || 'Expected function to throw';
    throw new Error(`Assertion failed: ${msg}`);
  }
}
