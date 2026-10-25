/**
 * Eviction risk detection
 * WebKit deletes script-written storage after 7 days without a visit,
 * unless the site runs as a home-screen app or storage is persisted
 */

export function isWebKit(userAgent: string, maxTouchPoints = 0): boolean {
  if (/iPhone|iPad|iPod/.test(userAgent)) return true;
  if (/Macintosh/.test(userAgent) && maxTouchPoints > 1) return true;
  return /AppleWebKit/.test(userAgent) && !/Chrome|Chromium|Android/.test(userAgent);
}

export function isStandalone(): boolean {
  const nav = navigator as Navigator & { standalone?: boolean };
  if (nav.standalone === true) return true;
  return (
    typeof globalThis.matchMedia === 'function' &&
    globalThis.matchMedia('(display-mode: standalone)').matches
  );
}

export async function detectEvictionRisk(): Promise<boolean> {
  if (typeof navigator === 'undefined') return false;
  if (!isWebKit(navigator.userAgent ?? '', navigator.maxTouchPoints ?? 0)) return false;
  if (isStandalone()) return false;
  try {
    return !(await navigator.storage?.persisted?.());
  } catch {
    return true;
  }
}
