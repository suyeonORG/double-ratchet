/**
 * /src/ratchet/x3dh.ts
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

/**
 * X3DH Key Agreement Implementation
 *
 * Implements the X3DH (Extended Triple Diffie-Hellman) key agreement protocol
 * for establishing shared secrets between two parties.
 *
 * @see https://whispersystems.org/docs/specifications/x3dh/
 */

import { INFO_TEXT, X3DH_FILL_BYTE, X3DH_SALT_LENGTH } from "../const";
import { Curve, ECPublicKey, IECKeyPair, Secret } from "../crypto";
import { Identity } from "../data";
import { ECDHPrivateKey, HMACCryptoKey } from "../type";
import { combine } from "../utils";

/**
 * Performs X3DH authentication for the initiator (Alice).
 * Calculates shared secret using Alice's identity and ephemeral keys
 * with Bob's identity, signed prekey, and optional one-time prekey.
 *
 * @param IKa Alice's identity key
 * @param EKa Alice's ephemeral key pair
 * @param IKb Bob's identity public key
 * @param SPKb Bob's signed prekey public key
 * @param OPKb Bob's one-time prekey public key (optional)
 * @returns Promise<HMACCryptoKey> Shared root key for ratchet initialization
 */
export async function authenticateA(
  IKa: Identity,
  EKa: IECKeyPair,
  IKb: ECPublicKey,
  SPKb: ECPublicKey,
  OPKb?: ECPublicKey,
): Promise<HMACCryptoKey> {
  // Perform required Diffie-Hellman exchanges
  const DH1 = await Curve.deriveBytes(IKa.exchangeKey.privateKey, SPKb);
  const DH2 = await Curve.deriveBytes(EKa.privateKey, IKb);
  const DH3 = await Curve.deriveBytes(EKa.privateKey, SPKb);

  let DH4 = new ArrayBuffer(0);
  if (OPKb) {
    // Include optional one-time prekey if present
    DH4 = await Curve.deriveBytes(EKa.privateKey, OPKb);
  }

  // Create 32-byte fill value (0xFF) - Signal X3DH specification
  const _F = new Uint8Array(X3DH_SALT_LENGTH);
  _F.fill(X3DH_FILL_BYTE);
  const F = _F.buffer as ArrayBuffer;

  // Combine all DH outputs with fill value
  const KM = combine(F, DH1, DH2, DH3, DH4);

  // Derive final key using HKDF
  const keys = await Secret.HKDF(KM, 1, void 0, INFO_TEXT);
  return await Secret.importHMAC(keys[0]);
}

/**
 * Performs X3DH authentication for the receiver (Bob).
 * Calculates shared secret using Bob's identity and signed prekey
 * with Alice's identity and ephemeral keys.
 *
 * @param IKb Bob's identity key
 * @param SPKb Bob's signed prekey pair
 * @param IKa Alice's identity public key
 * @param EKa Alice's ephemeral public key
 * @param OPKb Bob's one-time prekey private key (optional)
 * @returns Promise<HMACCryptoKey> Shared root key for ratchet initialization
 */
export async function authenticateB(
  IKb: Identity,
  SPKb: IECKeyPair,
  IKa: ECPublicKey,
  EKa: ECPublicKey,
  OPKb?: ECDHPrivateKey,
): Promise<HMACCryptoKey> {
  // Perform required Diffie-Hellman exchanges (same as Alice but with Bob's keys)
  const DH1 = await Curve.deriveBytes(SPKb.privateKey, IKa);
  const DH2 = await Curve.deriveBytes(IKb.exchangeKey.privateKey, EKa);
  const DH3 = await Curve.deriveBytes(SPKb.privateKey, EKa);

  let DH4 = new ArrayBuffer(0);
  if (OPKb) {
    // Include optional one-time prekey if present
    DH4 = await Curve.deriveBytes(OPKb, EKa);
  }

  // Create 32-byte fill value (0xFF) - Signal X3DH specification
  const _F = new Uint8Array(X3DH_SALT_LENGTH);
  _F.fill(X3DH_FILL_BYTE);
  const F = _F.buffer as ArrayBuffer;

  // Combine all DH outputs with fill value
  const KM = combine(F, DH1, DH2, DH3, DH4);

  // Derive final key using HKDF
  const keys = await Secret.HKDF(KM, 1, void 0, INFO_TEXT);
  return await Secret.importHMAC(keys[0]);
}
