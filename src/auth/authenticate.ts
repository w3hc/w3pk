/**
 * WebAuthn authentication flow
 */

import { startAuthentication } from "@simplewebauthn/browser";
import { AuthenticationError } from "../core/errors";
import { assertEthereumAddress } from "../utils/validation";
import type { ApiClient } from "../utils/api";
import type { AuthResult } from "./types";

export async function authenticate(
  apiClient: ApiClient,
  ethereumAddress: string
): Promise<AuthResult> {
  try {
    assertEthereumAddress(ethereumAddress);

    // Step 1: Begin authentication
    const beginResponse = await apiClient.post("/webauthn/authenticate/begin", {
      ethereumAddress,
    });

    if (!beginResponse.success || !beginResponse.data?.options) {
      throw new Error("Failed to get authentication options from server");
    }

    // Step 2: WebAuthn authentication
    const credential = await startAuthentication(beginResponse.data.options);

    // Step 3: Complete authentication
    const completeResponse = await apiClient.post(
      "/webauthn/authenticate/complete",
      {
        ethereumAddress,
        response: credential,
      }
    );

    if (!completeResponse.success) {
      throw new Error("Authentication verification failed");
    }

    return {
      verified: true,
      user: completeResponse.data?.user,
    };
  } catch (error) {
    throw new AuthenticationError(
      error instanceof Error ? error.message : "Authentication failed",
      error
    );
  }
}

export async function login(apiClient: ApiClient): Promise<AuthResult> {
  try {
    // Step 1: Begin usernameless authentication
    const beginResponse = await apiClient.post(
      "/webauthn/authenticate/usernameless/begin",
      {}
    );

    if (!beginResponse.success || !beginResponse.data?.options) {
      throw new Error(
        "Failed to get usernameless authentication options from server"
      );
    }

    // Step 2: WebAuthn authentication
    const credential = await startAuthentication(beginResponse.data.options);

    // Step 3: Complete authentication
    const completeResponse = await apiClient.post(
      "/webauthn/authenticate/usernameless/complete",
      {
        response: credential,
      }
    );

    if (!completeResponse.success) {
      throw new Error("Usernameless authentication verification failed");
    }

    return {
      verified: true,
      user: completeResponse.data?.user,
    };
  } catch (error) {
    throw new AuthenticationError(
      error instanceof Error
        ? error.message
        : "Usernameless authentication failed",
      error
    );
  }
}
