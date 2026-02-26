/**
 * Node.js Inspection Module
 *
 * Provides filesystem-based code inspection capabilities for analyzing web3 applications
 * from the server-side or during development. Scans application source code and generates
 * security reports via the Rukh API.
 *
 * @module inspect/node
 */

import { promises as fs } from 'fs';
import path from 'path';

/**
 * Configuration options for Node.js-based application inspection
 */
export interface InspectOptions {
  /**
   * The root directory of the application to inspect
   * @default process.cwd()
   */
  appPath?: string;

  /**
   * File patterns to include (glob patterns)
   * @default ['**\/*.ts', '**\/*.tsx', '**\/*.js', '**\/*.jsx', '**\/*.json']
   */
  includePatterns?: string[];

  /**
   * Directories to exclude from inspection
   * @default ['node_modules', 'dist', '.next', '.git', 'build', 'coverage']
   */
  excludeDirs?: string[];

  /**
   * Maximum file size in KB to include
   * @default 500
   */
  maxFileSizeKB?: number;

  /**
   * Focus mode: filters files to only include those relevant to specific features
   * - 'transactions': Only files with signing, transactions, or blockchain operations
   * - 'all': Include all files (default)
   * @default 'all'
   */
  focusMode?: 'transactions' | 'all';
}

/**
 * Result of the code gathering operation
 */
export interface InspectResult {
  /**
   * The generated markdown content with all collected code
   */
  markdown: string;

  /**
   * List of files that were included
   */
  includedFiles: string[];

  /**
   * Total size in KB of all included files
   */
  totalSizeKB: number;
}

/**
 * Checks if file content is relevant to transactions/signing operations
 *
 * Scans file content and filename for keywords related to blockchain transactions,
 * message signing, smart contracts, and web3 operations.
 *
 * @param content - The file content to analyze
 * @param filename - The name of the file being checked
 * @returns True if the file contains transaction-related code
 * @internal
 */
function isTransactionRelevant(content: string, filename: string): boolean {
  const transactionKeywords = [
    // Signing operations
    'signMessage',
    'signTypedData',
    'sign(',
    'signature',
    'personalSign',
    'eth_sign',
    'sendTransaction',

    // Transaction operations
    'transaction',
    'sendTx',
    'executeTx',
    'Contract.connect',
    'signer.send',
    'wallet.send',
    'provider.send',
    'eth_sendTransaction',
    'eth_sendRawTransaction',

    // Blockchain interaction
    'Contract(',
    'ethers.Contract',
    'new Contract',
    'ContractFactory',
    'deployContract',

    // W3PK specific
    'w3pk.sign',
    'w3pk.send',
    'Web3Passkey',
    'useW3PK',

    // Smart contract calls
    'call(',
    'estimateGas',
    'gasLimit',
    'gasPrice',
    'maxFeePerGas',
    'maxPriorityFeePerGas',

    // Web3 providers
    'JsonRpcProvider',
    'Web3Provider',
    'BrowserProvider',

    // EIP-7702
    'EIP7702',
    'authorization',
    'delegation',
  ];

  const lowerContent = content.toLowerCase();
  const lowerFilename = filename.toLowerCase();

  // Check if filename suggests transaction relevance
  if (
    lowerFilename.includes('transaction') ||
    lowerFilename.includes('sign') ||
    lowerFilename.includes('wallet') ||
    lowerFilename.includes('contract') ||
    lowerFilename.includes('blockchain') ||
    lowerFilename.includes('web3') ||
    lowerFilename.includes('ethers')
  ) {
    return true;
  }

  // Check content for transaction-related keywords
  return transactionKeywords.some(keyword =>
    lowerContent.includes(keyword.toLowerCase())
  );
}

/**
 * Recursively walks a directory tree and collects matching files
 *
 * Traverses the directory structure, applying filters based on file patterns,
 * size limits, and focus mode settings.
 *
 * @param dir - The directory path to walk
 * @param options - Inspection options with filters and limits
 * @param rootDir - The root directory for calculating relative paths
 * @returns Array of file objects with path, content, and relative path
 * @internal
 */
async function walkDirectory(
  dir: string,
  options: Required<InspectOptions>,
  rootDir: string
): Promise<{ path: string; content: string; relativePath: string }[]> {
  const files: { path: string; content: string; relativePath: string }[] = [];

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(rootDir, fullPath);

      if (entry.isDirectory()) {
        // Skip excluded directories
        if (options.excludeDirs.includes(entry.name)) {
          continue;
        }

        // Recursively walk subdirectory
        const subFiles = await walkDirectory(fullPath, options, rootDir);
        files.push(...subFiles);
      } else if (entry.isFile()) {
        // Check if file matches include patterns
        const ext = path.extname(entry.name);
        const shouldInclude = options.includePatterns.some(pattern => {
          // Simple pattern matching for common extensions
          if (pattern.includes('*')) {
            const patternExt = pattern.split('.').pop();
            return ext === `.${patternExt}`;
          }
          return entry.name === pattern;
        });

        if (!shouldInclude) {
          continue;
        }

        // Check file size
        const stats = await fs.stat(fullPath);
        const fileSizeKB = stats.size / 1024;

        if (fileSizeKB > options.maxFileSizeKB) {
          console.warn(`Skipping ${relativePath} (${fileSizeKB.toFixed(2)} KB exceeds limit)`);
          continue;
        }

        // Read file content
        const content = await fs.readFile(fullPath, 'utf-8');

        // Apply focus mode filter if enabled
        if (options.focusMode === 'transactions') {
          if (!isTransactionRelevant(content, entry.name)) {
            continue;
          }
        }

        files.push({ path: fullPath, content, relativePath });
      }
    }
  } catch (error) {
    console.error(`Error reading directory ${dir}:`, error);
  }

  return files;
}

/**
 * Gathers application code and generates a markdown document
 *
 * @param options - Configuration options for the inspection
 * @returns An object containing the markdown content and metadata
 *
 * @example
 * ```typescript
 * const result = await gatherCode({
 *   appPath: '../genji-passkey',
 *   includePatterns: ['**\/*.ts', '**\/*.tsx']
 * });
 *
 * console.log(`Collected ${result.includedFiles.length} files`);
 * console.log(`Total size: ${result.totalSizeKB} KB`);
 * ```
 */
export async function gatherCode(options: InspectOptions = {}): Promise<InspectResult> {
  const opts: Required<InspectOptions> = {
    appPath: options.appPath || process.cwd(),
    includePatterns: options.includePatterns || [
      '**/*.ts',
      '**/*.tsx',
      '**/*.js',
      '**/*.jsx',
      '**/*.json'
    ],
    excludeDirs: options.excludeDirs || [
      'node_modules',
      'dist',
      '.next',
      '.git',
      'build',
      'coverage',
      '.cache',
      'out',
      '.vercel',
      '.turbo'
    ],
    maxFileSizeKB: options.maxFileSizeKB || 500,
    focusMode: options.focusMode || 'all'
  };

  // Resolve app path
  const appPath = path.resolve(opts.appPath);

  // Check if app path exists
  try {
    await fs.access(appPath);
  } catch (error) {
    throw new Error(`App path does not exist: ${appPath}`);
  }

  // Walk directory and collect files
  const files = await walkDirectory(appPath, opts, appPath);

  // Generate markdown
  let markdown = `# Application Code Inspection\n\n`;
  markdown += `**Inspected Path:** \`${appPath}\`\n\n`;
  markdown += `**Files Collected:** ${files.length}\n\n`;
  markdown += `**Focus Mode:** ${opts.focusMode}\n\n`;
  markdown += `**Timestamp:** ${new Date().toISOString()}\n\n`;
  markdown += `---\n\n`;

  if (opts.focusMode === 'transactions') {
    markdown += `## Analysis Focus\n\n`;
    markdown += `This inspection is focused on **transaction and signing operations**. Only files containing:\n\n`;
    markdown += `- Message signing (signMessage, signTypedData, etc.)\n`;
    markdown += `- Transaction sending (sendTransaction, eth_sendTransaction, etc.)\n`;
    markdown += `- Smart contract interactions (Contract calls, deployments)\n`;
    markdown += `- Blockchain providers and wallets\n`;
    markdown += `- W3PK signing/transaction methods\n`;
    markdown += `- EIP-7702 authorization/delegation\n\n`;
    markdown += `---\n\n`;
  }

  // Add table of contents
  markdown += `## Table of Contents\n\n`;
  files.forEach(file => {
    markdown += `- [\`${file.relativePath}\`](#${file.relativePath.replace(/[^a-z0-9]/gi, '-').toLowerCase()})\n`;
  });
  markdown += `\n---\n\n`;

  // Add file contents
  markdown += `## Files\n\n`;

  for (const file of files) {
    const ext = path.extname(file.relativePath).slice(1);
    const language = ext === 'tsx' || ext === 'ts' ? 'typescript' :
                     ext === 'jsx' || ext === 'js' ? 'javascript' :
                     ext === 'json' ? 'json' : ext;

    markdown += `### \`${file.relativePath}\`\n\n`;
    markdown += '```' + language + '\n';
    markdown += file.content;
    markdown += '\n```\n\n';
    markdown += `---\n\n`;
  }

  // Calculate total size
  const totalSizeKB = files.reduce((sum, file) => {
    return sum + Buffer.byteLength(file.content, 'utf-8') / 1024;
  }, 0);

  return {
    markdown,
    includedFiles: files.map(f => f.relativePath),
    totalSizeKB: Math.round(totalSizeKB * 100) / 100
  };
}

/**
 * Inspects an application and returns a security report via Rukh API
 *
 * @param appPath - Path to the application to inspect
 * @param rukhUrl - The Rukh API endpoint URL
 * @param context - The context name to use (should have an instruction file with report format)
 * @param model - The AI model to use ('anthropic', 'mistral', or 'openai')
 * @param focusMode - Focus on 'transactions' or include 'all' files
 * @returns A markdown-formatted security report
 *
 * @example
 * ```typescript
 * const report = await inspect(
 *   '../genji-passkey',
 *   'https://rukh.w3hc.org',
 *   'w3pk',
 *   'anthropic',
 *   'transactions'
 * );
 *
 * console.log(report);
 * // Outputs:
 * // # Genji Passkey Report
 * // ## Available Methods
 * // ### Method #1: Sign Message
 * // ...
 * ```
 */
export async function inspect(
  appPath: string,
  rukhUrl: string = 'https://rukh.w3hc.org',
  context: string = 'w3pk',
  model: 'anthropic' | 'mistral' | 'openai' = 'anthropic',
  focusMode: 'transactions' | 'all' = 'transactions'
): Promise<string> {
  // Gather application code with focus mode
  const result = await gatherCode({ appPath, focusMode });

  console.log(`Inspected ${result.includedFiles.length} files (${result.totalSizeKB} KB) [Focus: ${focusMode}]`);

  // Default message that triggers the structured report
  const message = 'Analyze this application and provide a security report listing all transaction and signing methods.';

  // Prepare form data
  const formData = new FormData();
  formData.append('message', message);
  formData.append('model', model);
  formData.append('context', context);

  // Create a blob from the markdown content
  const blob = new Blob([result.markdown], { type: 'text/markdown' });
  formData.append('file', blob, 'app-code.md');

  // Send request to Rukh API
  const response = await fetch(`${rukhUrl}/ask`, {
    method: 'POST',
    body: formData
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Rukh API error: ${response.status} - ${error}`);
  }

  const data = await response.json();
  return data.response || data.message || JSON.stringify(data);
}
