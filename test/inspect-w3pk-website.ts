import { gatherCode } from '../src/inspect/index.js';

(async () => {
  const result = await gatherCode({
    appPath: '../w3pk-website',
    maxFileSizeKB: 500,
    focusMode: 'transactions' // Focus on transactions and signing
  });

  console.log(result.markdown);
  console.error('\n---\nStats: ' + result.includedFiles.length + ' files, ' + result.totalSizeKB + ' KB [Focus: transactions]');
})();
