/**
 * Eviction risk: WebKit outside a home-screen app with storage not persisted
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Wallet } from "ethers";
import { Web3Passkey } from "../src/index";
import { detectEvictionRisk, isWebKit } from "../src/utils/eviction";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  assertEqual,
} from "./test-utils";

const UA = {
  iphoneSafari:
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
  iphoneChrome:
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1",
  ipadDesktopMode:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  macSafari:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  epiphany:
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 Epiphany/46.0",
  macChrome:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  androidChrome:
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
  firefox:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0",
};

class MemoryStorage {
  private items = new Map<string, string>();
  get length() {
    return this.items.size;
  }
  key(i: number) {
    return [...this.items.keys()][i] ?? null;
  }
  getItem(k: string) {
    return this.items.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.items.set(k, String(v));
  }
  removeItem(k: string) {
    this.items.delete(k);
  }
  clear() {
    this.items.clear();
  }
}

const localStorage = new MemoryStorage();
(globalThis as any).localStorage = localStorage;
(globalThis as any).window = {
  location: { hostname: "localhost", origin: "http://localhost" },
  localStorage,
};

function setBrowser(options: {
  userAgent?: string;
  maxTouchPoints?: number;
  persisted?: boolean | "missing";
  standaloneMedia?: boolean;
  navigatorStandalone?: boolean;
}) {
  const nav: any =
    options.userAgent === undefined
      ? undefined
      : {
          userAgent: options.userAgent,
          maxTouchPoints: options.maxTouchPoints ?? 0,
          standalone: options.navigatorStandalone,
          storage:
            options.persisted === "missing"
              ? undefined
              : { persisted: async () => options.persisted ?? false },
        };
  Object.defineProperty(globalThis, "navigator", {
    value: nav,
    configurable: true,
    writable: true,
  });
  (globalThis as any).matchMedia = (query: string) => ({
    matches: query === "(display-mode: standalone)" && !!options.standaloneMedia,
  });
}

async function runTests() {
  startTestSuite("Eviction Risk Tests");

  await runTest("WebKit detection", async () => {
    assertEqual(isWebKit(UA.iphoneSafari), true, "iOS Safari");
    assertEqual(isWebKit(UA.iphoneChrome), true, "iOS Chrome");
    assertEqual(isWebKit(UA.ipadDesktopMode, 5), true, "iPadOS desktop mode");
    assertEqual(isWebKit(UA.macSafari), true, "macOS Safari");
    assertEqual(isWebKit(UA.epiphany), true, "desktop non-Safari WebKit");
    assertEqual(isWebKit(UA.macChrome), false, "macOS Chrome");
    assertEqual(isWebKit(UA.androidChrome), false, "Android Chrome");
    assertEqual(isWebKit(UA.firefox), false, "Firefox");
    passTest("all iOS browsers and desktop WebKit");
  });

  await runTest("Safari tab with storage not persisted is at risk", async () => {
    setBrowser({ userAgent: UA.iphoneSafari, persisted: false });
    assertEqual(await detectEvictionRisk(), true, "iOS Safari tab");
    setBrowser({ userAgent: UA.macSafari, persisted: false });
    assertEqual(await detectEvictionRisk(), true, "macOS Safari tab");
    setBrowser({ userAgent: UA.iphoneSafari, persisted: "missing" });
    assertEqual(await detectEvictionRisk(), true, "missing persisted() counts as not persisted");
    passTest("evictionRisk: true");
  });

  await runTest("Home-screen app or persisted storage is not at risk", async () => {
    setBrowser({ userAgent: UA.iphoneSafari, standaloneMedia: true });
    assertEqual(await detectEvictionRisk(), false, "display-mode: standalone");
    setBrowser({ userAgent: UA.iphoneSafari, navigatorStandalone: true });
    assertEqual(await detectEvictionRisk(), false, "navigator.standalone");
    setBrowser({ userAgent: UA.macSafari, persisted: true });
    assertEqual(await detectEvictionRisk(), false, "persisted");
    passTest("evictionRisk: false");
  });

  await runTest("Chromium and Firefox are not at risk", async () => {
    for (const userAgent of [UA.macChrome, UA.androidChrome, UA.firefox]) {
      setBrowser({ userAgent, persisted: true });
      assertEqual(await detectEvictionRisk(), false, `${userAgent} persisted`);
      setBrowser({ userAgent, persisted: false });
      assertEqual(await detectEvictionRisk(), false, `${userAgent} not persisted`);
    }
    passTest("evictionRisk: false");
  });

  await runTest("No navigator is not at risk", async () => {
    setBrowser({});
    assertEqual(await detectEvictionRisk(), false, "no navigator");
    passTest("evictionRisk: false");
  });

  await runTest("getBackupStatus reports evictionRisk", async () => {
    localStorage.clear();
    const sdk = new Web3Passkey();
    (sdk as any).currentUser = {
      username: "alice",
      ethereumAddress: Wallet.fromPhrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      ).address,
      credentialId: "test-credential",
    };

    setBrowser({ userAgent: UA.iphoneSafari, persisted: false });
    assertEqual((await sdk.getBackupStatus()).evictionRisk, true, "Safari tab");
    setBrowser({ userAgent: UA.iphoneSafari, persisted: true });
    assertEqual((await sdk.getBackupStatus()).evictionRisk, false, "computed fresh");
    passTest("evictionRisk in BackupStatus");
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
