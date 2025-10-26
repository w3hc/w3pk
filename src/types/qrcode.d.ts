/**
 * Type declarations for optional qrcode module
 * This allows the code to compile even when qrcode is not installed
 */

declare module 'qrcode' {
  export interface QRCodeToDataURLOptions {
    errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H';
    width?: number;
    margin?: number;
  }

  export function toDataURL(
    text: string,
    options?: QRCodeToDataURLOptions
  ): Promise<string>;

  export default {
    toDataURL,
  };
}
