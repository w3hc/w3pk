/**
 * API client for backend communication
 */

import { ApiError } from "../core/errors";
import type { ApiResponse } from "../types";

export class ApiClient {
  constructor(private baseUrl: string, private timeout: number = 30000) {}

  private async fetchWithTimeout(
    url: string,
    options: RequestInit
  ): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  async post<T = any>(
    endpoint: string,
    body: any,
    options?: RequestInit
  ): Promise<ApiResponse<T>> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.baseUrl}${endpoint}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...options?.headers,
          },
          body: JSON.stringify(body),
          ...options,
        }
      );

      if (!response.ok) {
        throw new ApiError(
          `API request failed: ${response.statusText}`,
          response.status
        );
      }

      return await response.json();
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError("Network request failed", undefined, error);
    }
  }

  async get<T = any>(
    endpoint: string,
    options?: RequestInit
  ): Promise<ApiResponse<T>> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.baseUrl}${endpoint}`,
        {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            ...options?.headers,
          },
          ...options,
        }
      );

      if (!response.ok) {
        throw new ApiError(
          `API request failed: ${response.statusText}`,
          response.status
        );
      }

      return await response.json();
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError("Network request failed", undefined, error);
    }
  }
}
