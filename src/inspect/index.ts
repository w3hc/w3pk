/**
 * Inspection module - browser-compatible by default
 *
 * This is the default export for browsers. It analyzes the currently running application.
 * For Node.js filesystem scanning, use: import { inspectNode } from 'w3pk/inspect/node'
 */

// Browser version (default)
export { inspect, inspectNow } from './browser';
export type { BrowserInspectOptions, BrowserInspectResult } from './browser';
