import "./setup";
import { createWeb3Passkey } from "../src/index";
import { startTestSuite, endTestSuite, runTest, passTest } from "./test-utils";

function assert(condition: unknown, message: string): void {
  if (!condition) throw new Error(message);
  passTest(message);
}

async function loggedErrors(config: Parameters<typeof createWeb3Passkey>[0]): Promise<unknown[][]> {
  const logged: unknown[][] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => {
    logged.push(args);
  };
  try {
    await createWeb3Passkey(config).login().catch(() => {});
  } finally {
    console.error = original;
  }
  return logged;
}

async function runTests() {
  startTestSuite("SDK Config");

  await runTest("debug: true logs errors from the instance config", async () => {
    const logged = await loggedErrors({ debug: true });
    assert(logged.length === 1 && logged[0][0] === "[w3pk]", "the failed login is logged");
  });

  await runTest("debug defaults to off", async () => {
    assert((await loggedErrors({})).length === 0, "nothing is logged");
  });

  await runTest("onError replaces the debug log", async () => {
    const seen: unknown[] = [];
    const logged = await loggedErrors({ debug: true, onError: (error) => seen.push(error) });
    assert(seen.length === 1, "onError gets the error");
    assert(logged.length === 0, "nothing else is logged");
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
