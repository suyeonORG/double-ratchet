/**
 * /src/crypto/crypto.ts
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

export interface ICryptoEngine {
  name: string;
  crypto: Crypto;
}

let engine: ICryptoEngine | null = null;

if (typeof self !== "undefined") {
  engine = {
    crypto: (self as unknown as { crypto: Crypto }).crypto,
    name: "WebCrypto",
  };
}
/**
 * Sets the WebCrypto engine for cryptographic operations.
 */
export function setEngine(name: string, crypto: Crypto) {
  engine = {
    crypto,
    name,
  };
}

/**
 * Returns the current WebCrypto engine.
 * Throws error if no engine is configured.
 */
export function getEngine(): ICryptoEngine {
  if (!engine) {
    throw new Error("WebCrypto engine is empty. Use setEngine to resolve it.");
  }
  return engine;
}
