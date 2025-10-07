/**
 * WebAuthn registration flow
 */

import { startRegistration } from "@simplewebauthn/browser";
import { RegistrationError } from "../core/errors";
import { assertUsername, assertEthereumAddress } from "../utils/validation";
import type { ApiClient } from "../utils/api";
import type { RegisterOptions } from "./types";

export async function register(
  apiClient: ApiClient,
  options: RegisterOptions
): Promise<void> {
  try {
    const { username, ethereumAddress } = options;

    // Validate inputs
    assertUsername(username);
    assertEthereumAddress(ethereumAddress);

    // Step 1: Begin registration
    const beginResponse = await apiClient.post("/webauthn/register/begin", {
      username,
      ethereumAddress,
    });

    if (!beginResponse.success || !beginResponse.data?.options) {
      throw new Error("Failed to get registration options from server");
    }

    // Step 2: WebAuthn registration
    const credential = await startRegistration(beginResponse.data.options);

    // Step 3: Complete registration
    const completeResponse = await apiClient.post(
      "/webauthn/register/complete",
      {
        ethereumAddress,
        response: credential,
      }
    );

    if (!completeResponse.success) {
      throw new Error("Registration verification failed");
    }
  } catch (error) {
    throw new RegistrationError(
      error instanceof Error ? error.message : "Registration failed",
      error
    );
  }
}
