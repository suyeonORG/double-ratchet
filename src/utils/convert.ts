/**
 * /src/utils/convert.ts
 * -------------------------------------------------
 * Double Ratchet Protocol Implementation
 *
 * Authors (Université Libre de Bruxelles ULB):
 * @suyeonORG, @ChaosArnhug, @KTBASECURITY, @Draimy
 *
 * - Signal Protocol Specifications by Trevor Perrin & Moxie Marlinspike
 *   https://signal.org/docs/specifications/doubleratchet/
 *   https://signal.org/docs/specifications/x3dh/
 *
 * - Original 2key-ratchet implementation by Peculiar Ventures, Inc. Under MIT license
 *   https://github.com/PeculiarVentures/2key-ratchet
 *
 * @license MIT
 */

export class Convert {
  /**
   * Converts string to ArrayBuffer
   */
  public static FromBinary(data: string): ArrayBuffer {
    const bytes = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      bytes[i] = data.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Converts ArrayBuffer to string
   */
  public static ToBinary(data: ArrayBuffer): string {
    const bytes = new Uint8Array(data);
    let result = "";
    for (let i = 0; i < bytes.length; i++) {
      result += String.fromCharCode(bytes[i]);
    }
    return result;
  }

  /**
   * Converts string to ArrayBuffer using UTF-8 encoding
   */
  public static FromString(data: string): ArrayBuffer {
    const encoder = new TextEncoder();
    return encoder.encode(data).buffer;
  }

  /**
   * Converts ArrayBuffer to string using UTF-8 encoding
   */
  public static ToString(data: ArrayBuffer | Uint8Array): string {
    const decoder = new TextDecoder();
    return decoder.decode(data);
  }

  /**
   * Converts ArrayBuffer to hex string
   */
  public static ToHex(data: ArrayBuffer): string {
    const bytes = new Uint8Array(data);
    return Array.from(bytes)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Converts hex string to ArrayBuffer
   */
  public static FromHex(hex: string): ArrayBuffer {
    // Remove any whitespace and ensure even length
    hex = hex.replace(/\s/g, "");
    if (hex.length % 2 !== 0) {
      throw new Error("Invalid hex string length");
    }

    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes.buffer;
  }

  /**
   * Converts ArrayBuffer to Base64 string
   */
  public static ToBase64(data: ArrayBuffer): string {
    const bytes = new Uint8Array(data);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Converts Base64 string to ArrayBuffer
   */
  public static FromBase64(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Converts ArrayBuffer to Base64URL string
   */
  public static ToBase64Url(data: ArrayBuffer): string {
    return Convert.ToBase64(data)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  /**
   * Converts Base64URL string to ArrayBuffer
   */
  public static FromBase64Url(base64url: string): ArrayBuffer {
    // Add padding if needed
    let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    const padding = base64.length % 4;
    if (padding) {
      base64 += "=".repeat(4 - padding);
    }
    return Convert.FromBase64(base64);
  }
}
