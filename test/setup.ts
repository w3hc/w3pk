/**
 * Test environment setup
 * Mock browser APIs for Node.js testing
 */

// In-memory storage for testing
const storage = new Map<string, string>();

// Mock localStorage for Node.js with working implementation
export const mockLocalStorage: Storage = {
  getItem: (key: string) => storage.get(key) || null,
  setItem: (key: string, value: string) => { storage.set(key, value); },
  removeItem: (key: string) => { storage.delete(key); },
  clear: () => { storage.clear(); },
  get length() { return storage.size; },
  key: (index: number) => Array.from(storage.keys())[index] || null
};

// Mock window and localStorage globally for Node.js
if (typeof window === 'undefined') {
  (global as any).window = {
    localStorage: mockLocalStorage,
    location: {
      hostname: 'localhost'
    }
  };
}
