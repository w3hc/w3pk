/**
 * Strict CBOR decoder (RFC 8949) for attestation objects and COSE keys.
 */

import { decodeCbor, decodeCborExact, CborError } from "../src/auth/cbor";
import { runTestSuite, assert } from "./test-utils";

const hex = (s: string) => new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));

function refused(bytes: Uint8Array, what: string) {
  return () => {
    let error: unknown;
    try {
      decodeCborExact(bytes);
    } catch (e) {
      error = e;
    }
    assert(error instanceof CborError, `${what} should be refused`);
  };
}

runTestSuite("CBOR Decoder Tests", [
  {
    name: "decodes RFC 8949 Appendix A integers",
    fn: () => {
      const cases: [string, number][] = [
        ["00", 0],
        ["17", 23],
        ["1818", 24],
        ["1903e8", 1000],
        ["1a000f4240", 1000000],
        ["1b000000e8d4a51000", 1000000000000],
        ["20", -1],
        ["3863", -100],
        ["3903e7", -1000],
      ];
      for (const [input, expected] of cases) {
        assert(decodeCborExact(hex(input)) === expected, `${input} should decode to ${expected}`);
      }
    },
  },
  {
    name: "decodes strings, arrays and maps",
    fn: () => {
      const bytes = decodeCborExact(hex("4401020304")) as Uint8Array;
      assert(bytes instanceof Uint8Array && bytes.join() === "1,2,3,4", "byte string");
      assert(decodeCborExact(hex("6449455446")) === "IETF", "text string");
      const array = decodeCborExact(hex("8301820203820405")) as unknown[];
      assert(JSON.stringify(array) === "[1,[2,3],[4,5]]", "nested array");
      const map = decodeCborExact(hex("a201020304")) as Map<number, number>;
      assert(map.get(1) === 2 && map.get(3) === 4, "integer-keyed map");
      const textMap = decodeCborExact(hex("a26161016162820203")) as Map<string, unknown>;
      assert(textMap.get("a") === 1 && JSON.stringify(textMap.get("b")) === "[2,3]", "text-keyed map");
    },
  },
  {
    name: "decodeCbor returns the end offset of the first item",
    fn: () => {
      const { value, end } = decodeCbor(hex("ff1903e8ff"), 1);
      assert(value === 1000 && end === 4, `got ${value} ending at ${end}`);
    },
  },
  { name: "trailing bytes are refused", fn: refused(hex("0000"), "trailing bytes") },
  { name: "truncated byte string is refused", fn: refused(hex("440102"), "a truncated byte string") },
  { name: "truncated argument is refused", fn: refused(hex("1903"), "a truncated argument") },
  { name: "truncated map is refused", fn: refused(hex("a20102"), "a truncated map") },
  { name: "indefinite length is refused", fn: refused(hex("5f42010243030405ff"), "an indefinite byte string") },
  { name: "reserved additional info is refused", fn: refused(hex("1c"), "additional info 28") },
  { name: "tags are refused", fn: refused(hex("c11a514b67b0"), "a tag") },
  { name: "floats are refused", fn: refused(hex("f93c00"), "a half float") },
  { name: "simple values are refused", fn: refused(hex("f5"), "true") },
  { name: "integers beyond 2^53 are refused", fn: refused(hex("1bffffffffffffffff"), "a 64-bit integer") },
  { name: "duplicate map keys are refused", fn: refused(hex("a201020103"), "a duplicate key") },
  { name: "array map keys are refused", fn: refused(hex("a1800102"), "an array key") },
  { name: "invalid UTF-8 is refused", fn: refused(hex("62c328"), "invalid UTF-8") },
  { name: "deep nesting is refused", fn: refused(new Uint8Array([...new Array(32).fill(0x81), 0x00]), "32 nested arrays") },
]);
