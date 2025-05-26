/**
 * /src/sym_ratchet.ts
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
 * Symmetric Ratchet Implementation
 *
 * Implements the symmetric ratchet component of the Double Ratchet algorithm.
 * Handles forward-secure encryption/decryption with automatic key rotation.
 */

import { INFO_MESSAGE_KEYS } from "./const";
import { Secret } from "./crypto";
import { HMACCryptoKey, ISymmetricKDFResult } from "./type";
import { IJsonSerializable } from "./type";

/** Constants for Chain Key Derivation Function (KDF_CK) */
const CIPHER_KEY_KDF_INPUT = new Uint8Array([1]).buffer;
const ROOT_KEY_KDF_INPUT = new Uint8Array([2]).buffer;

/**
 * Result interface for symmetric ratchet encryption/decryption operations.
 * Contains both the message content and the HMAC key for authentication.
 */
export interface ICipherMessage {
  /** Encrypted or decrypted message content */
  cipherText: ArrayBuffer;
  /** HMAC key for message authentication in SignedMessage */
  hmacKey: CryptoKey;
}

/** JSON serialization interface for symmetric ratchets */
export interface IJsonSymmetricRatchet {
  /** Current message counter */
  counter: number;
  /** Root key for this ratchet chain */
  rootKey: CryptoKey;
}

/**
 * Abstract base class for symmetric ratchet implementations.
 * Provides common functionality for forward-secure message chains.
 */
export abstract class SymmetricRatchet implements IJsonSerializable {
  /**
   * Creates a symmetric ratchet instance from JSON data.
   *
   * @param obj JSON object containing ratchet state
   * @returns Promise<T> Reconstructed ratchet instance
   */
  public static async fromJSON<T extends SymmetricRatchet>(
    this: new (rootKey: CryptoKey, debug?: boolean) => T,
    obj: IJsonSymmetricRatchet
  ): Promise<T> {
    const res = new this(obj.rootKey);
    res.fromJSON(obj);
    return res;
  }

  /** Current message counter for this ratchet chain */
  public counter = 0;

  /**
   * Current symmetric ratchet key
   */
  public rootKey: HMACCryptoKey;

  constructor(rootKey: CryptoKey, protected debug: boolean = false) {
    this.rootKey = rootKey;
  }

  public async toJSON() {
    return {
      counter: this.counter,
      rootKey: this.rootKey,
    } as IJsonSymmetricRatchet;
  }

  public async fromJSON(obj: IJsonSymmetricRatchet) {
    this.counter = obj.counter;
    this.rootKey = obj.rootKey;
  }

  /**
   * calculates new keys by rootKey KDF_CK(ck)
   * https://whispersystems.org/docs/specifications/doubleratchet/#external-functions
   *
   * @protected
   * @param {CryptoKey} rootKey
   * @returns
   *
   * @memberOf SymmetricRatchet
   */
  protected async calculateKey(rootKey: CryptoKey) {
    const cipherKeyBytes = await Secret.sign(
      rootKey,
      CIPHER_KEY_KDF_INPUT as any
    );
    const nextRootKeyBytes = await Secret.sign(
      rootKey,
      ROOT_KEY_KDF_INPUT as any
    );

    const res: ISymmetricKDFResult = {
      cipher: cipherKeyBytes,
      rootKey: await Secret.importHMAC(nextRootKeyBytes, this.debug),
    };
    return res;
  }

  /**
   * Move to next step of ratchet
   *
   * @protected
   * @returns
   *
   * @memberOf SymmetricRatchet
   */
  protected async click() {
    const rootKey = this.rootKey;
    const res = await this.calculateKey(rootKey);
    this.rootKey = res.rootKey;
    this.counter++;
    return res.cipher;
  }
}

/**
 * Implementation of Sending chain
 *
 * @export
 * @class SendingRatchet
 * @extends {SymmetricRatchet}
 */
export class SendingRatchet extends SymmetricRatchet {
  /**
   * Encrypts message
   *
   * @param {ArrayBuffer} message
   * @param {ArrayBuffer} [associatedData] - Optional associated data for AEAD
   * @returns CipherMessage type
   *
   * @memberOf SendingRatchet
   */
  public async encrypt(message: ArrayBuffer, associatedData?: ArrayBuffer) {
    const cipherKey = await this.click();
    const keys = await Secret.HKDF(cipherKey, 3, void 0, INFO_MESSAGE_KEYS);
    const aesKey = await Secret.importAES(keys[0].slice(0, 32), this.debug);
    const hmacKey = await Secret.importHMAC(keys[1], this.debug);

    const iv = keys[2].slice(0, 12);

    const cipherText = await Secret.encrypt(
      aesKey,
      message,
      iv,
      associatedData
    );

    return {
      cipherText,
      hmacKey,
    } as ICipherMessage;
  }
}

export interface IJsonReceivingRatchet extends IJsonSymmetricRatchet {
  messageKeys: { [counter: number]: ArrayBuffer };
}

// Interface to represent a cached message key
export interface ICachedMessageKey {
  counter: number;
  key: ArrayBuffer;
}

export class ReceivingRatchet extends SymmetricRatchet {
  protected messageKeys: { [counter: number]: ArrayBuffer } = {};

  // Track when keys were created for potential expiry (better security)
  protected messageKeysCreationTime: { [counter: number]: number } = {};

  // Maximum age of cached message keys (1 hour in milliseconds)
  protected readonly MAX_CACHED_KEY_AGE = 60 * 60 * 1000;

  // Maximum number of cached message keys (prevent DoS)
  protected readonly MAX_CACHED_KEYS = 2000;

  public async toJSON() {
    const res: IJsonReceivingRatchet = (await super.toJSON()) as any;
    res.messageKeys = this.messageKeys;
    return res;
  }

  public async fromJSON(obj: IJsonReceivingRatchet) {
    await super.fromJSON(obj);
    if (Array.isArray(obj.messageKeys)) {
      this.messageKeys = {};
      for (let i = 0; i < obj.messageKeys.length; i++) {
        this.messageKeys[i] = obj.messageKeys[i];
        this.messageKeysCreationTime[i] = Date.now();
      }
    } else {
      this.messageKeys = obj.messageKeys || {};
      // Initialize creation times for existing keys
      for (const counter in this.messageKeys) {
        if (this.messageKeys.hasOwnProperty(counter)) {
          this.messageKeysCreationTime[counter] = Date.now();
        }
      }
    }
  }

  public async decrypt(
    message: ArrayBuffer,
    counter: number,
    associatedData?: ArrayBuffer
  ) {
    const cipherKey = await this.getKey(counter);
    // calculate keys
    const keys = await Secret.HKDF(cipherKey, 3, void 0, INFO_MESSAGE_KEYS);
    const aesKey = await Secret.importAES(keys[0].slice(0, 32), this.debug); // Truncate to 256 bits for AES
    const hmacKey = await Secret.importHMAC(keys[1], this.debug);

    const iv = keys[2].slice(0, 12);

    const cipherText = await Secret.decrypt(
      aesKey,
      message,
      iv,
      associatedData
    );

    return {
      cipherText,
      hmacKey,
    } as ICipherMessage;
  }

  // Clean up expired keys
  protected cleanupExpiredKeys() {
    const now = Date.now();
    let keysRemoved = 0;

    for (const counter in this.messageKeysCreationTime) {
      if (this.messageKeysCreationTime.hasOwnProperty(counter)) {
        if (
          now - this.messageKeysCreationTime[counter] >
          this.MAX_CACHED_KEY_AGE
        ) {
          delete this.messageKeys[counter];
          delete this.messageKeysCreationTime[counter];
          keysRemoved++;
        }
      }
    }

    if (keysRemoved > 0) {
      console.log(`Removed ${keysRemoved} expired message keys`);
    }
  }

  // Enforce maximum key cache size to prevent DoS
  protected enforceMaxCacheSize() {
    const keyCounters = Object.keys(this.messageKeys).map((k) =>
      parseInt(k, 10)
    );

    if (keyCounters.length > this.MAX_CACHED_KEYS) {
      // Sort by counter (oldest messages first)
      keyCounters.sort((a, b) => a - b);

      // Remove oldest keys until we're under the limit
      const keysToRemove = keyCounters.length - this.MAX_CACHED_KEYS;
      for (let i = 0; i < keysToRemove; i++) {
        const counter = keyCounters[i];
        delete this.messageKeys[counter];
        delete this.messageKeysCreationTime[counter];
      }

      console.log(
        `Enforced maximum key cache size, removed ${keysToRemove} oldest keys`
      );
    }
  }

  protected async getKey(counter: number) {
    // First periodically clean up expired keys
    this.cleanupExpiredKeys();

    // Check if we already have the key cached
    if (this.messageKeys[counter] !== undefined) {
      const key = this.messageKeys[counter];
      // Remove the key after use (better security)
      delete this.messageKeys[counter];
      delete this.messageKeysCreationTime[counter];
      return key;
    }

    // If requested counter is less than current counter, message is too old
    if (counter < this.counter) {
      throw new Error(
        `Message with counter ${counter} is too old. Current counter is ${this.counter}`
      );
    }

    // Fast-forward chain to derive all intermediate keys up to the needed one
    while (this.counter <= counter) {
      const cipherKey = await this.click();
      // Store skipped keys in our hash map
      if (this.counter - 1 < counter) {
        this.messageKeys[this.counter - 1] = cipherKey;
        this.messageKeysCreationTime[this.counter - 1] = Date.now();
      } else {
        this.enforceMaxCacheSize();
        return cipherKey;
      }
    }

    // We should never reach here
    throw new Error("Failed to derive message key");
  }
}
