import { inspect } from '../src/inspect/index.js';

(async () => {
  const result = await inspect({
    appPath: '../genji-passkey',
    maxFileSizeKB: 500,
    focusMode: 'transactions' // Focus on transactions and signing
  });

  console.log(result.markdown);
  console.error('\n---\nStats: ' + result.includedFiles.length + ' files, ' + result.totalSizeKB + ' KB [Focus: transactions]');
})();
