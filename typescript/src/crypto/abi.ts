import { encodeAbiParameters } from "viem";
import type { MetaData, Bytes32 } from "../spf-client.js";

/**
 * SpfParameter structure for encoding
 *
 * Note: This interface should match the one in spf-client.ts
 */
export interface SpfParameter {
  readonly metaData: MetaData;
  readonly payload: readonly Bytes32[];
}

/**
 * SpfRun structure for encoding
 */
export interface SpfRun {
  readonly spfLibrary: string;
  readonly program: string;
  readonly parameters: readonly SpfParameter[];
}

/**
 * SpfAccess structure for encoding
 */
export interface SpfAccess {
  readonly ciphertext: string;
  readonly changes: readonly SpfParameter[];
}

/**
 * Encode an SpfRun structure using viem's tree-shakeable ABI encoding
 *
 * @param spfRun - SpfRun structure to encode
 * @returns ABI-encoded data as hex string with 0x prefix
 */
export function encodeSpfRunAbi(spfRun: SpfRun): string {
  // Convert to the format viem expects
  const value = {
    spfLibrary: spfRun.spfLibrary as `0x${string}`,
    program: spfRun.program as `0x${string}`,
    parameters: spfRun.parameters.map((p) => ({
      metaData: BigInt(p.metaData),
      payload: p.payload.map(pl => pl as `0x${string}`),
    })),
  };

  return encodeAbiParameters(
    [
      {
        name: 'spfRun',
        type: 'tuple',
        components: [
          { name: 'spfLibrary', type: 'bytes32' },
          { name: 'program', type: 'bytes32' },
          {
            name: 'parameters',
            type: 'tuple[]',
            components: [
              { name: 'metaData', type: 'uint256' },
              { name: 'payload', type: 'bytes32[]' }
            ]
          }
        ]
      }
    ],
    [value]
  );
}

/**
 * Encode an SpfAccess structure using viem's tree-shakeable ABI encoding
 *
 * @param spfAccess - SpfAccess structure to encode
 * @returns ABI-encoded data as hex string with 0x prefix
 */
export function encodeSpfAccessAbi(spfAccess: SpfAccess): string {
  // Convert to the format viem expects
  const value = {
    ciphertext: spfAccess.ciphertext as `0x${string}`,
    changes: spfAccess.changes.map((c) => ({
      metaData: BigInt(c.metaData),
      payload: c.payload.map(pl => pl as `0x${string}`),
    })),
  };

  return encodeAbiParameters(
    [
      {
        name: 'spfAccess',
        type: 'tuple',
        components: [
          { name: 'ciphertext', type: 'bytes32' },
          {
            name: 'changes',
            type: 'tuple[]',
            components: [
              { name: 'metaData', type: 'uint256' },
              { name: 'payload', type: 'bytes32[]' }
            ]
          }
        ]
      }
    ],
    [value]
  );
}
