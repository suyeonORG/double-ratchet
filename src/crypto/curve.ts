/**
 * /src/crypto/curve.ts
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

import { ed25519, x25519 } from "@noble/curves/ed25519";
import { ECDHPrivateKey } from "../type";
import { IECKeyPair } from "./key_pair";
import { ECPublicKey } from "./public_key";

/** Supported curve types for modern cryptography */
type CurveType = "Ed25519" | "X25519";

/** Interface for cryptographic keys with raw byte access */
interface IKeyWithRawBytes {
  _rawBytes: Uint8Array;
}

/**
 * Modern elliptic curve cryptography implementation using Ed25519/X25519.
 * Provides key generation, ECDH, and digital signature operations.
 */
export class Curve {
  /** X25519 curve name for Diffie-Hellman key exchange */
  public static NAMED_CURVE_DH = "X25519";

  /** Ed25519 curve name for digital signatures */
  public static NAMED_CURVE_SIGN = "Ed25519";

  /** Digest algorithm for compatibility (Ed25519 uses SHA-512 internally) */
  public static DIGEST_ALGORITHM = "SHA-512";

  /**
   * Generates a new elliptic curve key pair.
   *
   * @param type Curve type - "Ed25519" for signing or "X25519" for key exchange
   * @param extractable Whether the private key should be extractable
   * @returns Promise<IECKeyPair> Generated key pair
   * @throws Error if unsupported curve type is specified
   */
  public static async generateKeyPair(
    type: CurveType,
    extractable: boolean
  ): Promise<IECKeyPair> {
    if (type === "X25519") {
      const privateKeyBytes = x25519.utils.randomPrivateKey();
      const publicKeyBytes = x25519.getPublicKey(privateKeyBytes);

      const privateKey = this.createPrivateKey(
        privateKeyBytes,
        "X25519",
        extractable
      );
      const publicKey = await ECPublicKey.createFromBytes(
        publicKeyBytes,
        "X25519"
      );

      return { privateKey, publicKey } as IECKeyPair;
    } else if (type === "Ed25519") {
      const privateKeyBytes = ed25519.utils.randomPrivateKey();
      const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);

      const privateKey = this.createPrivateKey(
        privateKeyBytes,
        "Ed25519",
        extractable
      );
      const publicKey = await ECPublicKey.createFromBytes(
        publicKeyBytes,
        "Ed25519"
      );

      return { privateKey, publicKey } as IECKeyPair;
    }

    throw new Error(
      `Unsupported key type: ${type}. Only Ed25519 and X25519 are supported.`
    );
  }

  /**
   * Performs X25519 Elliptic Curve Diffie-Hellman key exchange.
   * Derives a 32-byte shared secret from private and public keys.
   *
   * @param privateKey X25519 private key
   * @param publicKey X25519 public key
   * @returns ArrayBuffer 32-byte shared secret
   * @throws Error if invalid key format or length
   */
  public static deriveBytes(
    privateKey: ECDHPrivateKey,
    publicKey: ECPublicKey
  ): ArrayBuffer {
    const privateKeyBytes = (privateKey as unknown as IKeyWithRawBytes)
      ._rawBytes;
    const publicKeyBytes = new Uint8Array(publicKey.serialize());

    if (!privateKeyBytes || privateKeyBytes.length !== 32) {
      throw new Error("Invalid private key for X25519");
    }
    if (publicKeyBytes.length !== 32) {
      throw new Error("Invalid public key for X25519");
    }

    const sharedSecret = x25519.getSharedSecret(
      privateKeyBytes,
      publicKeyBytes
    );
    return sharedSecret.buffer;
  }

  /**
   * Verifies an Ed25519 digital signature.
   *
   * @param signingKey Ed25519 public key used for verification
   * @param message Original message that was signed
   * @param signature 64-byte Ed25519 signature to verify
   * @returns boolean True if signature is valid, false otherwise
   */
  public static verify(
    signingKey: ECPublicKey,
    message: ArrayBuffer,
    signature: ArrayBuffer
  ): boolean {
    try {
      const publicKeyBytes = new Uint8Array(signingKey.serialize());
      const messageBytes = new Uint8Array(message);
      const signatureBytes = new Uint8Array(signature);

      if (publicKeyBytes.length !== 32) {
        throw new Error("Invalid public key size for Ed25519");
      }
      if (signatureBytes.length !== 64) {
        throw new Error("Invalid signature size for Ed25519");
      }

      return ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
    } catch (error) {
      console.warn("Ed25519 signature verification failed:", error);
      return false;
    }
  }

  /**
   * Creates an Ed25519 digital signature.
   *
   * @param signingKey Ed25519 private key used for signing
   * @param message Message content to sign
   * @returns Promise<ArrayBuffer> 64-byte Ed25519 signature
   * @throws Error if invalid private key format
   */
  public static async sign(
    signingKey: ECDHPrivateKey,
    message: ArrayBuffer
  ): Promise<ArrayBuffer> {
    const privateKeyBytes = (signingKey as unknown as IKeyWithRawBytes)
      ._rawBytes;
    const messageBytes = new Uint8Array(message);

    if (!privateKeyBytes || privateKeyBytes.length !== 32) {
      throw new Error("Invalid private key for Ed25519");
    }

    const signature = ed25519.sign(messageBytes, privateKeyBytes);
    return signature.buffer;
  }

  /**
   * Serializes an EC key pair to JSON format.
   * Stores raw bytes for Ed25519/X25519 keys.
   *
   * @param key Key pair to serialize
   * @returns Promise<any> JSON representation of the key pair
   * @throws Error if key cannot be serialized
   */
  public static async ecKeyPairToJson(key: IECKeyPair): Promise<object> {
    const privateKeyBytes = (key.privateKey as unknown as IKeyWithRawBytes)
      ._rawBytes;
    const publicKeyBytes = key.publicKey.serialize();

    if (!privateKeyBytes) {
      throw new Error("Cannot serialize key: missing raw bytes");
    }

    const algorithm = key.privateKey.algorithm;
    return {
      privateKey: Array.from(privateKeyBytes),
      publicKey: Array.from(new Uint8Array(publicKeyBytes)),
      algorithm,
      thumbprint: await key.publicKey.thumbprint(),
    };
  }

  /**
   * Reconstructs an EC key pair from JSON format.
   * Handles both legacy and modern key formats.
   *
   * @param data JSON key data containing privateKey, publicKey, and algorithm
   * @returns Promise<IECKeyPair> Reconstructed key pair
   * @throws Error if invalid key data or unsupported algorithm
   */
  public static async ecKeyPairFromJson(data: unknown): Promise<IECKeyPair> {
    const keyData = data as {
      privateKey?: number[];
      publicKey?: number[];
      algorithm?: { name?: string; namedCurve?: string };
    };
    if (!keyData.privateKey || !keyData.publicKey) {
      throw new Error("Invalid key data: missing privateKey or publicKey");
    }

    const privateKeyBytes = new Uint8Array(keyData.privateKey);
    const publicKeyBytes = new Uint8Array(keyData.publicKey);

    // Determine curve type from algorithm
    const algorithmName =
      keyData.algorithm?.name || keyData.algorithm?.namedCurve;
    let curveType: CurveType;

    if (algorithmName === "X25519" || algorithmName === "ECDH") {
      curveType = "X25519";
    } else if (algorithmName === "Ed25519" || algorithmName === "ECDSA") {
      curveType = "Ed25519";
    } else {
      throw new Error(`Unsupported algorithm: ${algorithmName}`);
    }

    const privateKey = this.createPrivateKey(privateKeyBytes, curveType, true);
    const publicKey = await ECPublicKey.createFromBytes(
      publicKeyBytes,
      curveType
    );

    return { privateKey, publicKey } as IECKeyPair;
  }

  /**
   * Creates a custom private key object with raw bytes storage.
   * This is needed because we use @noble/curves directly instead of WebCrypto.
   *
   * @param rawBytes Raw private key bytes (32 bytes)
   * @param curveName Curve type name
   * @param extractable Whether the key should be extractable
   * @returns CryptoKey Private key object
   */
  private static createPrivateKey(
    rawBytes: Uint8Array,
    curveName: CurveType,
    extractable: boolean
  ): CryptoKey {
    return {
      algorithm: {
        name: curveName,
        namedCurve: curveName,
      },
      extractable,
      type: "private" as KeyType,
      usages:
        curveName === "X25519"
          ? (["deriveKey", "deriveBits"] as KeyUsage[])
          : (["sign"] as KeyUsage[]),
      _rawBytes: rawBytes,
    } as CryptoKey;
  }
}
