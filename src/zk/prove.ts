/**
 * Groth16 proofs over a passkey-bound secret the caller never sees
 */

import { CryptoError } from "../core/errors";
import {
  verifyZkArtifacts,
  type ZkArtifactBytes,
  type ZkArtifactPins,
  type ZkArtifactSources,
} from "./artifacts";
import { BABYJUB_FIELD, deriveBabyJubKeyPair, randomBabyJubScalar } from "./babyjub";
import { SEMAPHORE_PRF_LABEL, loadSemaphoreSecretScalar } from "./semaphore";

/** PRF label for `zkProve`'s own secret, unreachable from `derivePrfSecret(tag)` */
export const ZK_PRF_LABEL = "w3pk-zk-v1";

export type ZkSignal = bigint | number | string | ZkSignal[];

/** Circuit inputs by signal name, as snarkjs takes them */
export type ZkInputs = Record<string, ZkSignal>;

export interface ZkProveArtifacts extends ZkArtifactSources {
  /** CIDs the artifacts must match, e.g. from `readZkArtifactPins` */
  pins: ZkArtifactPins;
}

/**
 * - `"zk"`: a Baby Jubjub private key derived from the passkey under the
 *   `w3pk-zk-v1` label
 * - `"semaphore"`: the `secretScalar` of `getSemaphoreIdentity(tag)`'s identity
 */
export type ZkSecretSource = "zk" | "semaphore";

/**
 * A Poseidon input: a string names another input (the secret, a caller
 * input, a random input or an earlier derivation), a bigint is a constant
 */
export type ZkDerivationTerm = string | bigint;

export interface ZkProveOptions {
  /** Default `"zk"` */
  secret?: ZkSecretSource;
  /** Circuit input that receives the secret. Default `"secret"` */
  secretInput?: string;
  /**
   * Inputs w3pk computes as `Poseidon(terms)`, in order, e.g.
   * `{ voteSecret: ["secret", "proposalId", 1n] }`. 1 to 16 terms each
   */
  derive?: Record<string, ZkDerivationTerm[]>;
  /** Inputs w3pk fills with fresh random scalars in `[1, l)` and discards */
  random?: string[];
}

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export interface ZkProveResult {
  proof: Groth16Proof;
  publicSignals: string[];
}

interface WitnessPlan {
  inputs: ZkInputs;
  secretInput: string;
  random: string[];
  derive: [string, ZkDerivationTerm[]][];
}

function toField(value: ZkSignal, name: string): bigint {
  let field: bigint;
  try {
    if (typeof value === "bigint") field = value;
    else if (typeof value === "number" && Number.isSafeInteger(value)) field = BigInt(value);
    else if (typeof value === "string" && value.trim() !== "") field = BigInt(value);
    else throw new Error();
  } catch {
    throw new CryptoError(`Input '${name}' is not a field element`);
  }
  if (field < 0n || field >= BABYJUB_FIELD) {
    throw new CryptoError(`Input '${name}' is not in the BN254 scalar field`);
  }
  return field;
}

function planWitness(
  publicInputs: ZkInputs,
  extraWitness: ZkInputs,
  options: ZkProveOptions
): WitnessPlan {
  const inputs: ZkInputs = { ...publicInputs };
  for (const [name, value] of Object.entries(extraWitness)) {
    if (name in inputs) {
      throw new CryptoError(`Input '${name}' is in both publicInputs and extraWitness`);
    }
    inputs[name] = value;
  }

  const secretInput = options.secretInput ?? "secret";
  const random = options.random ?? [];
  const derive = Object.entries(options.derive ?? {});

  const known = new Set(Object.keys(inputs));
  for (const name of [secretInput, ...random, ...derive.map(([name]) => name)]) {
    if (typeof name !== "string" || name.length === 0) {
      throw new CryptoError("Input names must be non-empty strings");
    }
    if (known.has(name)) {
      throw new CryptoError(`Input '${name}' is set by w3pk and can't be given or declared twice`);
    }
    known.add(name);
  }

  const available = new Set([secretInput, ...random]);
  for (const [name, terms] of derive) {
    if (!Array.isArray(terms) || terms.length < 1 || terms.length > 16) {
      throw new CryptoError(`Derivation '${name}' needs 1 to 16 terms`);
    }
    for (const term of terms) {
      if (typeof term === "bigint") {
        toField(term, `${name} constant`);
      } else if (typeof term === "string" && term in inputs) {
        toField(inputs[term], term);
      } else if (!(typeof term === "string" && available.has(term))) {
        throw new CryptoError(`Derivation '${name}' uses '${String(term)}', which isn't an input set before it`);
      }
    }
    available.add(name);
  }

  return { inputs, secretInput, random, derive };
}

async function loadPoseidon(): Promise<(inputs: bigint[]) => bigint> {
  let poseidon: Record<string, (inputs: bigint[]) => bigint>;
  try {
    poseidon = (await import("poseidon-lite")) as unknown as typeof poseidon;
  } catch (error) {
    throw new CryptoError(
      "zkProve derivations require poseidon-lite. Install with: pnpm add poseidon-lite",
      error
    );
  }
  return (inputs) => poseidon[`poseidon${inputs.length}`](inputs);
}

function zkSecretScalar(secret: Uint8Array): bigint {
  try {
    return deriveBabyJubKeyPair(secret).privateKey;
  } finally {
    secret.fill(0);
  }
}

interface Groth16Prover {
  prove(input: ZkInputs): Promise<{ proof: any; publicSignals: any[] }>;
  close(): void;
}

async function startInThreadProver({ wasm, zkey }: ZkArtifactBytes): Promise<Groth16Prover> {
  let snarkjs: typeof import("snarkjs");
  try {
    snarkjs = await import("snarkjs");
  } catch (error) {
    throw new CryptoError("ZK proofs require snarkjs. Install with: pnpm add snarkjs", error);
  }
  return {
    async prove(input) {
      try {
        return await snarkjs.groth16.fullProve(input, wasm, zkey);
      } catch (error) {
        throw new CryptoError(
          `Failed to generate proof: ${error instanceof Error ? error.message : String(error)}`,
          error
        );
      }
    },
    close() {},
  };
}

/**
 * The worker is `dist/zk/prove-worker.mjs`, next to `dist/index.mjs`, which
 * bundlers pick up from the `new Worker(new URL(...))` pattern. The CommonJS
 * build has no `import.meta.url`, so it can't start the worker.
 */
async function startWorkerProver({ wasm, zkey }: ZkArtifactBytes): Promise<Groth16Prover> {
  let worker: Worker;
  try {
    worker = new Worker(new URL("./zk/prove-worker.mjs", import.meta.url), { type: "module" });
  } catch (error) {
    throw new CryptoError("Failed to start the proving worker (it needs w3pk's ESM build)", error);
  }

  const reply = () =>
    new Promise<any>((resolve, reject) => {
      worker.onmessage = (event) =>
        event.data?.error ? reject(new CryptoError(event.data.error)) : resolve(event.data);
      worker.onerror = (event) => {
        event.preventDefault();
        reject(new CryptoError(`Proving worker failed: ${event.message || "failed to load"}`));
      };
    });

  try {
    await reply();
  } catch (error) {
    worker.terminate();
    throw error;
  }

  return {
    prove(input) {
      const result = reply();
      worker.postMessage({ input, wasm, zkey });
      return result;
    },
    close: () => worker.terminate(),
  };
}

/**
 * Prove with a secret from `deriveSecret(label)` placed in the witness, plus
 * the derived and random inputs `options` declares. Everything that can fail
 * without the passkey (options, dependencies, artifact pins, the worker)
 * fails before `deriveSecret` prompts. The secret and random values never
 * leave this call: a proof whose public signals contain one is refused.
 *
 * @param deriveSecret - Returns the 32-byte PRF secret for a label
 * @throws ZkArtifactMismatchError when an artifact doesn't match its pin
 * @throws CryptoError on invalid inputs, missing dependencies or a failed proof
 */
export async function zkProve(
  deriveSecret: (label: string) => Promise<Uint8Array>,
  artifacts: ZkProveArtifacts,
  publicInputs: ZkInputs,
  extraWitness: ZkInputs = {},
  options: ZkProveOptions = {}
): Promise<ZkProveResult> {
  const plan = planWitness(publicInputs, extraWitness, options);
  const source = options.secret ?? "zk";
  if (source !== "zk" && source !== "semaphore") {
    throw new CryptoError(`Unknown secret source '${String(source)}'`);
  }
  const toScalar = source === "semaphore" ? await loadSemaphoreSecretScalar() : zkSecretScalar;
  const poseidon = plan.derive.length > 0 ? await loadPoseidon() : undefined;

  const bytes = await verifyZkArtifacts(
    { wasm: artifacts.wasm, zkey: artifacts.zkey },
    artifacts.pins
  );
  const prover =
    typeof Worker === "undefined"
      ? await startInThreadProver(bytes)
      : await startWorkerProver(bytes);

  try {
    const secret = toScalar(
      await deriveSecret(source === "semaphore" ? SEMAPHORE_PRF_LABEL : ZK_PRF_LABEL)
    );
    const hidden = new Set([secret.toString()]);
    const witness: ZkInputs = { ...plan.inputs, [plan.secretInput]: secret };
    for (const name of plan.random) {
      const r = randomBabyJubScalar();
      witness[name] = r;
      hidden.add(r.toString());
    }
    for (const [name, terms] of plan.derive) {
      witness[name] = poseidon!(
        terms.map((term) => (typeof term === "bigint" ? term : toField(witness[term], term)))
      );
    }

    const { proof, publicSignals } = await prover.prove(witness);
    const signals = publicSignals.map(String);
    if (signals.some((signal) => hidden.has(signal))) {
      throw new CryptoError("The circuit makes the secret or a random input public; proof refused");
    }
    return {
      proof: {
        pi_a: proof.pi_a.map(String),
        pi_b: proof.pi_b.map((pair: unknown[]) => pair.map(String)),
        pi_c: proof.pi_c.map(String),
        protocol: proof.protocol,
        curve: proof.curve,
      },
      publicSignals: signals,
    };
  } finally {
    prover.close();
  }
}
