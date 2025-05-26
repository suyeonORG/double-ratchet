/**
 * /src/utils/buffer.ts
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
export function combine(...buffers: ArrayBuffer[]): ArrayBuffer {
  const totalLength = buffers.reduce(
    (sum, buffer) => sum + buffer.byteLength,
    0
  );
  const result = new ArrayBuffer(totalLength);
  const view = new Uint8Array(result);

  let offset = 0;
  for (const buffer of buffers) {
    view.set(new Uint8Array(buffer), offset);
    offset += buffer.byteLength;
  }

  return result;
}

/**
 * Checks if two ArrayBuffers are equal using constant-time comparison
 * Prevents timing attacks on signature/MAC verification
 * Replacement for pvtsutils.isEqual
 */
export function isEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  const viewA = new Uint8Array(a);
  const viewB = new Uint8Array(b);

  // Constant-time comparison to prevent timing oracle attacks
  let result = 0;
  for (let i = 0; i < viewA.length; i++) {
    result |= viewA[i] ^ viewB[i];
  }

  return result === 0;
}
