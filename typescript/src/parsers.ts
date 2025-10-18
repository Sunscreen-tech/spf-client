import { getWasmModule } from "@sunscreen/spf-client/spf-wasm-loader";
import type {
  BitWidth,
  RunStatus,
  RunStatusSuccess,
  RunStatusFailed,
  RunStatusPending,
  RunPayload,
  DecryptionStatus,
  DecryptionStatusSuccess,
  DecryptionStatusFailed,
  DecryptionStatusPending,
} from "./spf-client.js";

/**
 * Decryption status for raw polynomial bytes (before parsing to plaintext)
 * Used by OTP re-encryption workflow where polynomial bytes need local decryption
 */
export type DecryptionStatusSuccessRaw = {
  readonly status: "success";
  readonly payload: {
    readonly polyBytes: Uint8Array;
  };
};

/**
 * Discriminated union with raw polynomial bytes (before parsing to plaintext)
 * Used by OTP re-encryption workflow
 */
export type DecryptionStatusRaw =
  | DecryptionStatusPending
  | DecryptionStatusSuccessRaw
  | DecryptionStatusFailed;

/**
 * Parse and validate a string response
 * @internal
 */
export function parseStringResponse(data: unknown): string {
  if (typeof data !== "string") {
    throw new Error(`Expected string response, got ${typeof data}`);
  }
  return data;
}

/**
 * Parse and validate a run status response
 * @internal
 */
export function parseRunStatusResponse(data: unknown): RunStatus {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid status response");
  }

  const obj = data as Record<string, unknown>;
  const status = obj["status"];

  if (typeof status !== "string") {
    throw new Error("Missing or invalid status field");
  }

  // Return discriminated union based on status
  if (status === "success") {
    const payload = obj["payload"];
    const result: RunStatusSuccess = {
      status: "success",
      ...(payload !== undefined && payload !== null && typeof payload === "object"
        ? { payload: payload as RunPayload }
        : {}),
    };
    return result;
  }

  if (status === "failed") {
    const payload = obj["payload"];
    if (payload !== undefined && payload !== null && typeof payload === "object") {
      const result: RunStatusFailed = {
        status: "failed",
        payload: payload as { readonly message?: string },
      };
      return result;
    } else {
      const result: RunStatusFailed = {
        status: "failed",
      };
      return result;
    }
  }

  if (status === "pending" || status === "running" || status === "in_progress") {
    const result: RunStatusPending = {
      status: status,
    };
    return result;
  }

  throw new Error(`Unknown status: ${status}`);
}

/**
 * Parse and validate a decryption status response, returning raw polynomial bytes
 * This is the base parser used by both normal and OTP decryption workflows
 * @internal
 */
export function parseDecryptionStatusResponseRaw(
  data: unknown,
): DecryptionStatusRaw {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid decryption status response");
  }

  const obj = data as Record<string, unknown>;
  const status = obj["status"];

  if (typeof status !== "string") {
    throw new Error("Missing or invalid status field");
  }

  if (status === "success") {
    const payload = obj["payload"];
    if (
      typeof payload !== "object" ||
      payload === null ||
      !Array.isArray((payload as Record<string, unknown>)["value"])
    ) {
      throw new Error("Invalid success payload format");
    }

    // The server returns bincode-serialized polynomial bytes as a JSON array
    const valueArray = (payload as Record<string, unknown>)["value"];

    // Validate that all elements are numbers
    if (!Array.isArray(valueArray) || !valueArray.every((n): n is number => typeof n === "number")) {
      throw new Error("Invalid polynomial bytes format: expected number[]");
    }

    const result: DecryptionStatusSuccessRaw = {
      status: "success",
      payload: {
        polyBytes: new Uint8Array(valueArray),
      },
    };
    return result;
  }

  if (status === "failed") {
    const payload = obj["payload"];
    if (payload !== undefined && payload !== null && typeof payload === "object") {
      const result: DecryptionStatusFailed = {
        status: "failed",
        payload: payload as { readonly message?: string },
      };
      return result;
    } else {
      const result: DecryptionStatusFailed = {
        status: "failed",
      };
      return result;
    }
  }

  if (status === "pending" || status === "running" || status === "in_progress") {
    const result: DecryptionStatusPending = {
      status: status,
    };
    return result;
  }

  throw new Error(`Unknown decryption status: ${status}`);
}

/**
 * Parse and validate a decryption status response
 * Calls the raw parser and then parses polynomial bytes to plaintext
 * @internal
 */
export async function parseDecryptionStatusResponse(
  data: unknown,
  bitWidth: BitWidth,
  signed: boolean,
): Promise<DecryptionStatus> {
  // Get raw status with polynomial bytes
  const rawStatus = parseDecryptionStatusResponseRaw(data);

  // If success, parse the polynomial bytes to get the plaintext value
  if (rawStatus.status === "success") {
    const wasm = await getWasmModule();
    const parsedValue = wasm.parse_polynomial_to_value(
      rawStatus.payload.polyBytes,
      bitWidth,
      signed
    );

    const result: DecryptionStatusSuccess = {
      status: "success",
      payload: {
        value: parsedValue,
      },
    };
    return result;
  }

  // For pending, running, failed, or in_progress - return as-is
  return rawStatus;
}
