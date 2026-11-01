/**
 * Web Worker running snarkjs for `zkProve`. Posts `{ ready: true }` once
 * snarkjs loads, then answers each `{ input, wasm, zkey }` with
 * `{ proof, publicSignals }`. Failures post `{ error }`.
 */

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const snarkjs = import("snarkjs");

snarkjs.then(
  () => postMessage({ ready: true }),
  (error) =>
    postMessage({
      error: `ZK proofs require snarkjs. Install with: pnpm add snarkjs (${errorMessage(error)})`,
    })
);

onmessage = async (event: MessageEvent) => {
  try {
    const { input, wasm, zkey } = event.data;
    const { proof, publicSignals } = await (await snarkjs).groth16.fullProve(input, wasm, zkey);
    postMessage({ proof, publicSignals });
  } catch (error) {
    postMessage({ error: `Failed to generate proof: ${errorMessage(error)}` });
  }
};
