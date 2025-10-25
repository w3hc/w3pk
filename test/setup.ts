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

// Mock IndexedDB for Node.js test environment
(global as any).indexedDB = {
  open: () => {
    const request: any = {
      result: {
        objectStoreNames: { contains: () => false },
        createObjectStore: () => ({}),
        transaction: () => ({
          objectStore: () => ({
            put: () => ({ onsuccess: null, onerror: null }),
            get: () => ({ onsuccess: null, onerror: null }),
            delete: () => ({ onsuccess: null, onerror: null }),
          })
        })
      },
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null
    };
    // Simulate success
    setTimeout(() => {
      if (request.onupgradeneeded) request.onupgradeneeded();
      if (request.onsuccess) request.onsuccess();
    }, 0);
    return request;
  }
};
