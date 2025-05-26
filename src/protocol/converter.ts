/**
 * /src/protocol/converter.ts
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

import { ECPublicKey } from "../crypto";
import { Convert } from "../utils";

export class Ed25519PublicKeyConverter {
  public static async set(value: ECPublicKey) {
    return new Uint8Array(value.serialize());
  }

  public static async get(value: Uint8Array) {
    if (value.length !== 32) {
      throw new Error(
        `Invalid Ed25519 key length: ${value.length} bytes. Expected 32 bytes.`
      );
    }
    return ECPublicKey.createFromBytes(value.buffer as ArrayBuffer, "Ed25519");
  }
}

export class X25519PublicKeyConverter {
  public static async set(value: ECPublicKey) {
    return new Uint8Array(value.serialize());
  }

  public static async get(value: Uint8Array) {
    if (value.length !== 32) {
      throw new Error(
        `Invalid X25519 key length: ${value.length} bytes. Expected 32 bytes.`
      );
    }
    return ECPublicKey.createFromBytes(value.buffer as ArrayBuffer, "X25519");
  }
}

export const ECDSAPublicKeyConverter = Ed25519PublicKeyConverter;
export const ECDHPublicKeyConverter = X25519PublicKeyConverter;

export class DateConverter {
  public static async set(value: Date) {
    return new Uint8Array(Convert.FromString(value.toISOString()));
  }
  public static async get(value: Uint8Array) {
    return new Date(Convert.ToString(value));
  }
}
