/**
 * Minimal type declarations for optional qrcode module
 *
 * These types allow compilation even when qrcode is not installed.
 * For full type definitions, consumers can install @types/qrcode
 *
 * Note: qrcode is an optionalDependency - code gracefully degrades
 * when not available (see QRBackupCreator.createFallbackQRDataURL)
 *
 * @see https://www.npmjs.com/package/qrcode
 * @see https://www.npmjs.com/package/@types/qrcode
 */

declare module 'qrcode' {
  /**
   * Error correction levels for QR codes
   * - L (Low): 7% of data bytes can be restored
   * - M (Medium): 15% of data bytes can be restored
   * - Q (Quartile): 25% of data bytes can be restored
   * - H (High): 30% of data bytes can be restored
   *
   * w3pk uses 'H' for maximum damage tolerance
   */
  export type QRCodeErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H';

  /**
   * Options for QR code generation
   */
  export interface QRCodeToDataURLOptions {
    /**
     * Error correction level (default: 'M')
     * w3pk recommends 'H' for backup QR codes
     */
    errorCorrectionLevel?: QRCodeErrorCorrectionLevel;

    /**
     * Image type (default: 'image/png')
     */
    type?: 'image/png' | 'image/jpeg' | 'image/webp';

    /**
     * Quality for JPEG/WEBP (0-1, default: 0.92)
     */
    quality?: number;

    /**
     * Quiet zone margin in modules (default: 4)
     * w3pk uses 2 for compact QR codes
     */
    margin?: number;

    /**
     * Scale factor for the image (default: 4)
     */
    scale?: number;

    /**
     * Width of the image in pixels
     * w3pk uses 512 for optimal scanning
     */
    width?: number;

    /**
     * Custom colors for QR code
     */
    color?: {
      /**
       * Dark module color (default: '#000000')
       */
      dark?: string;
      /**
       * Light module color (default: '#ffffff')
       */
      light?: string;
    };
  }

  /**
   * Options for canvas and string rendering
   */
  export interface QRCodeRenderersOptions extends QRCodeToDataURLOptions {
    /**
     * Additional rendering options can be added here
     */
  }

  /**
   * Generate QR code as data URL (most commonly used)
   * @param text - Data to encode in QR code
   * @param options - QR code generation options
   * @returns Promise resolving to data URL (e.g., 'data:image/png;base64,...')
   */
  export function toDataURL(
    text: string,
    options?: QRCodeToDataURLOptions
  ): Promise<string>;

  /**
   * Generate QR code as data URL with callback (alternative signature)
   */
  export function toDataURL(
    text: string,
    callback: (error: Error | null, url: string) => void
  ): void;

  /**
   * Generate QR code as data URL with options and callback
   */
  export function toDataURL(
    text: string,
    options: QRCodeToDataURLOptions,
    callback: (error: Error | null, url: string) => void
  ): void;

  /**
   * Render QR code to canvas element
   * @param canvas - Canvas element to render to
   * @param text - Data to encode
   * @param options - Rendering options
   */
  export function toCanvas(
    canvas: HTMLCanvasElement,
    text: string,
    options?: QRCodeRenderersOptions
  ): Promise<void>;

  /**
   * Generate QR code as string (SVG or terminal output)
   * @param text - Data to encode
   * @param options - Rendering options
   */
  export function toString(
    text: string,
    options?: QRCodeRenderersOptions
  ): Promise<string>;

  /**
   * Default export with all methods
   * This is the primary import style used by w3pk
   */
  const QRCode: {
    toDataURL(
      text: string,
      options?: QRCodeToDataURLOptions
    ): Promise<string>;
    toCanvas(
      canvas: HTMLCanvasElement,
      text: string,
      options?: QRCodeRenderersOptions
    ): Promise<void>;
    toString(
      text: string,
      options?: QRCodeRenderersOptions
    ): Promise<string>;
  };

  export default QRCode;
}
