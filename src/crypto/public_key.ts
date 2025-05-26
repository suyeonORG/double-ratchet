/**
 * /src/crypto/public_key.ts
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

import { Convert, isEqual } from "../utils";
import { getEngine } from "./crypto";

type SupportedKeyType = "Ed25519" | "X25519";

/**
 * Implementation of EC public key - Ed25519/X25519 only
 *
 * @export
 * @class ECPublicKey
 */
export class ECPublicKey {
  /**
   * Creates new instance of ECPublicKey from CryptoKey
   *
   * @static
   * @param {CryptoKey} publicKey
   * @returns
   *
   * @memberOf ECPublicKey
   */
  public static async create(publicKey: CryptoKey) {
    const res = new this();
    const algName = publicKey.algorithm.name!.toUpperCase();

    if (
      !(
        algName === "ED25519" ||
        algName === "X25519" ||
        algName === "ECDH" ||
        algName === "ECDSA"
      )
    ) {
      throw new Error(
        `Error: Unsupported asymmetric key algorithm: ${algName}. Only Ed25519 and X25519 are supported.`
      );
    }
    if (publicKey.type !== "public") {
      throw new Error("Error: Expected key type to be public but it was not.");
    }
    res.key = publicKey;

    if ((publicKey as unknown as { _rawBytes?: Uint8Array })._rawBytes) {
      const keyWithBytes = publicKey as unknown as { _rawBytes: Uint8Array };
      res.serialized = keyWithBytes._rawBytes.buffer || keyWithBytes._rawBytes;
      res.id = await res.thumbprint();
      return res;
    }

    try {
      const jwk = await getEngine().crypto.subtle.exportKey("jwk", publicKey);
      if (!(jwk.x && jwk.y)) {
        throw new Error(
          "Wrong JWK data for EC public key. Parameters x and y are required."
        );
      }
      const x = Convert.FromBase64Url(jwk.x);
      const y = Convert.FromBase64Url(jwk.y);
      const xy = Convert.ToBinary(x) + Convert.ToBinary(y);
      res.serialized = Convert.FromBinary(xy);
      res.id = await res.thumbprint();
      return res;
    } catch (error) {
      throw new Error(`Failed to process public key: ${error}`);
    }
  }

  /**
   * Creates ECPublicKey from raw bytes (Ed25519/X25519 - 32 bytes each)
   */
  public static async createFromBytes(
    bytes: ArrayBuffer | Uint8Array,
    type: SupportedKeyType
  ) {
    const res = new this();

    const keyBytes =
      bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
    if (keyBytes.length !== 32) {
      throw new Error("Public key must be exactly 32 bytes for Ed25519/X25519");
    }

    res.serialized = keyBytes.buffer;
    res.id = await res.thumbprint();

    res.key = {
      algorithm: {
        name: type,
        namedCurve: type,
      },
      type: "public",
      extractable: true,
      usages: type === "X25519" ? [] : ["verify"],
      _rawBytes: keyBytes,
    } as CryptoKey;

    return res;
  }

  /**
   * Creates ECPublicKey from raw data - Ed25519/X25519 only
   *
   * @static
   * @param {ArrayBuffer} bytes
   * @param {SupportedKeyType} type Ed25519 | X25519
   * @returns
   *
   * @memberOf ECPublicKey
   */
  public static async importKey(bytes: ArrayBuffer, type: SupportedKeyType) {
    if (bytes.byteLength === 32) {
      return await this.createFromBytes(bytes, type);
    }

    if (bytes.byteLength === 64) {
      console.warn(
        "Legacy P-256 key format detected, but only Ed25519/X25519 are supported"
      );
      throw new Error(
        "Legacy key format not supported. Please use Ed25519/X25519 keys only."
      );
    }

    throw new Error(
      `Unsupported key length: ${bytes.byteLength} bytes. Ed25519/X25519 keys must be 32 bytes.`
    );
  }

  /**
   * Identity of ECPublicKey
   * HEX string of thumbprint of EC key
   *
   * @type {string}
   * @memberOf ECPublicKey
   */
  public id: string;

  /**
   * Crypto key
   *
   * @type {CryptoKey}
   * @memberOf ECPublicKey
   */
  public key: CryptoKey;

  /**
   * raw data of key
   *
   * @protected
   * @type {ArrayBuffer}
   * @memberOf ECPublicKey
   */
  protected serialized: ArrayBuffer;

  /**
   * Returns key in raw format
   *
   * @returns
   *
   * @memberOf ECPublicKey
   */
  public serialize() {
    return this.serialized;
  }

  /**
   * Returns SHA-256 digest of key using WebCrypto
   *
   * @returns
   *
   * @memberOf ECPublicKey
   */
  public async thumbprint() {
    const bytes = this.serialized;

    // Use WebCrypto for SHA-256
    const crypto =
      globalThis.crypto ||
      (globalThis as unknown as { webkitCrypto: Crypto }).webkitCrypto;
    if (!crypto || !crypto.subtle) {
      throw new Error("WebCrypto not available for SHA-256 hashing");
    }

    const thumbprint = await crypto.subtle.digest("SHA-256", bytes);
    return Convert.ToHex(thumbprint);
  }

  /**
   * Returns `true` if current is equal to given parameter
   *
   * @param {*} other
   * @returns
   *
   * @memberOf ECPublicKey
   */
  public async isEqual(other: unknown) {
    if (!(other && other instanceof ECPublicKey)) {
      return false;
    }

    return isEqual(this.serialized, other.serialized);
  }
}
