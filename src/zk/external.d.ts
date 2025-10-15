/**
 * Type declarations for optional ZK dependencies
 */

declare module "circomlibjs" {
  export function buildPoseidon(): Promise<any>;
  export function buildBabyjub(): Promise<any>;
  export function buildMimc7(): Promise<any>;
  export function buildPedersenHash(): Promise<any>;
  export function buildMimcSponge(): Promise<any>;
}

declare module "snarkjs" {
  export namespace groth16 {
    export function fullProve(
      input: any,
      wasmFile: string,
      zkeyFile: string
    ): Promise<{ proof: any; publicSignals: any }>;

    export function verify(
      vKey: any,
      publicSignals: any,
      proof: any
    ): Promise<boolean>;

    export function setup(
      r1csFile: string,
      ptauFile: string,
      zkeyFile: string
    ): Promise<void>;
  }

  export namespace zKey {
    export function exportVerificationKey(zkeyFile: string): Promise<any>;
    export function contribute(
      oldZkeyFile: string,
      newZkeyFile: string,
      name: string,
      entropy: string
    ): Promise<any>;
  }

  export namespace utils {
    export function unstringifyBigInts(obj: any): any;
    export function stringifyBigInts(obj: any): any;
  }
}
