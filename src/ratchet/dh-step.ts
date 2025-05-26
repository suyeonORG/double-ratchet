/**
 * /src/ratchet/dh-step.ts
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

import { DEFAULT_RATCHET_LIMITS, IRatchetLimits } from "../const";
import { ECPublicKey } from "../crypto";
import { Stack } from "../stack";
import { ReceivingRatchet, SendingRatchet } from "../sym_ratchet";
import { IJsonSerializable } from "../type";
import { IJsonDHRatchetStepEnhanced, ISkippedMessageKey } from "./types";

/**
 * Enhanced implementation of a Diffie-Hellman ratchet step
 * with better skipped message handling and cross-ratchet support.
 */
export class DHRatchetStepEnhanced implements IJsonSerializable {
  /**
   * Creates DHRatchetStepEnhanced instance from JSON object.
   *
   * @param obj JSON object containing step data
   * @returns Promise<DHRatchetStepEnhanced> Reconstructed step instance
   */
  public static async fromJSON(
    obj: IJsonDHRatchetStepEnhanced
  ): Promise<DHRatchetStepEnhanced> {
    const res = new this();
    await res.fromJSON(obj);
    return res;
  }

  /** Remote client's ratchet key (X25519) */
  public remoteRatchetKey?: ECPublicKey;

  /** Sending chain for this DH step */
  public sendingChain?: SendingRatchet;

  /** Receiving chain for this DH step */
  public receivingChain?: ReceivingRatchet;

  /** Thumbprint of the remote ratchet key for identification */
  public ratchetKeyId?: string;

  /** Last successfully decrypted message counter */
  public lastDecryptedCounter: number = -1;

  /** Skipped message keys for this step, keyed by counter */
  public skippedMessageKeys: { [counter: number]: ArrayBuffer } = {};

  /**
   * Serializes the DH ratchet step to JSON.
   *
   * @returns Promise<IJsonDHRatchetStepEnhanced> JSON representation
   */
  public async toJSON(): Promise<IJsonDHRatchetStepEnhanced> {
    const res: IJsonDHRatchetStepEnhanced = {};

    if (this.remoteRatchetKey) {
      res.remoteRatchetKey = this.remoteRatchetKey.key;
      res.ratchetKeyId = this.remoteRatchetKey.id;
    }
    if (this.sendingChain) {
      res.sendingChain = await this.sendingChain.toJSON();
    }
    if (this.receivingChain) {
      res.receivingChain = await this.receivingChain.toJSON();
    }

    res.lastDecryptedCounter = this.lastDecryptedCounter;
    res.skippedMessageKeys = {};
    for (const [counter, key] of Object.entries(this.skippedMessageKeys)) {
      res.skippedMessageKeys[counter] = key;
    }

    return res;
  }

  /**
   * Reconstructs the DH ratchet step from JSON.
   *
   * @param obj JSON object containing step data
   */
  public async fromJSON(obj: IJsonDHRatchetStepEnhanced): Promise<void> {
    if (obj.remoteRatchetKey) {
      this.remoteRatchetKey = await ECPublicKey.create(obj.remoteRatchetKey);
      this.ratchetKeyId = obj.ratchetKeyId || this.remoteRatchetKey.id;
    }
    if (obj.sendingChain) {
      this.sendingChain = await SendingRatchet.fromJSON(obj.sendingChain);
    }
    if (obj.receivingChain) {
      this.receivingChain = await ReceivingRatchet.fromJSON(obj.receivingChain);
    }

    this.lastDecryptedCounter = obj.lastDecryptedCounter || -1;
    this.skippedMessageKeys = obj.skippedMessageKeys || {};
  }
}

/**
 * Enhanced collection of DH ratchet steps with configurable limits
 * and improved skipped message key management following Signal spec.
 */
export class DHRatchetStepStackEnhanced extends Stack<DHRatchetStepEnhanced> {
  /** Hash map for O(1) lookup by ratchet key ID */
  private ratchetKeyLookup: { [keyId: string]: DHRatchetStepEnhanced } = {};

  /** Global skipped message keys across ALL DH steps */
  private globalSkippedKeys: { [compositeKey: string]: ISkippedMessageKey } =
    {};

  /** Configurable limits for DoS protection */
  private readonly limits: Required<IRatchetLimits>;

  /**
   * Creates a new DH ratchet step stack with configurable limits.
   *
   * @param limits Configuration limits for DoS protection
   */
  constructor(limits: IRatchetLimits = {}) {
    super(limits.maxRatchetSteps || DEFAULT_RATCHET_LIMITS.maxRatchetSteps);
    this.limits = { ...DEFAULT_RATCHET_LIMITS, ...limits };
  }

  /**
   * Adds a new DH ratchet step to the stack with cleanup.
   *
   * @param item DH ratchet step to add
   */
  public push(item: DHRatchetStepEnhanced): void {
    super.push(item);

    // Update lookup table
    if (item.ratchetKeyId) {
      this.ratchetKeyLookup[item.ratchetKeyId] = item;
    } else if (item.remoteRatchetKey) {
      item.ratchetKeyId = item.remoteRatchetKey.id;
      this.ratchetKeyLookup[item.ratchetKeyId] = item;
    }

    // Clean up old entries when stack overflows
    if (this.items.length > this.maxSize) {
      const removedItem = this.items[0]; // The item that was removed
      if (removedItem?.ratchetKeyId) {
        delete this.ratchetKeyLookup[removedItem.ratchetKeyId];
        this.cleanupSkippedKeysForRatchet(removedItem.ratchetKeyId);
      }
    }
  }

  /**
   * Gets DH ratchet step by remote ratchet key with O(1) lookup.
   *
   * @param remoteRatchetKey Remote client's ratchet key
   * @returns DHRatchetStepEnhanced | undefined Found step or undefined
   */
  public getStep(
    remoteRatchetKey: ECPublicKey
  ): DHRatchetStepEnhanced | undefined {
    return this.ratchetKeyLookup[remoteRatchetKey.id];
  }

  /**
   * Stores skipped message key globally with configurable limits.
   *
   * @param ratchetKeyId Ratchet key identifier
   * @param messageCounter Message counter within the ratchet
   * @param messageKey The message key to store
   */
  public storeSkippedMessageKey(
    ratchetKeyId: string,
    messageCounter: number,
    messageKey: ArrayBuffer
  ): void {
    const compositeKey = `${ratchetKeyId}:${messageCounter}`;

    // Enforce configurable limits
    if (
      Object.keys(this.globalSkippedKeys).length >= this.limits.maxSkippedKeys
    ) {
      this.cleanupExpiredSkippedKeys();

      // If still too many, remove oldest
      if (
        Object.keys(this.globalSkippedKeys).length >= this.limits.maxSkippedKeys
      ) {
        const oldestKey = Object.keys(this.globalSkippedKeys).sort(
          (a, b) =>
            this.globalSkippedKeys[a].timestamp -
            this.globalSkippedKeys[b].timestamp
        )[0];
        delete this.globalSkippedKeys[oldestKey];
      }
    }

    this.globalSkippedKeys[compositeKey] = {
      ratchetKeyId,
      messageCounter,
      messageKey,
      timestamp: Date.now(),
    };

    console.log(`Stored skipped message key: ${compositeKey}`);
  }

  /**
   * Retrieves and consumes skipped message key.
   *
   * @param ratchetKeyId Ratchet key identifier
   * @param messageCounter Message counter within the ratchet
   * @returns ArrayBuffer | undefined Message key if found, undefined otherwise
   */
  public consumeSkippedMessageKey(
    ratchetKeyId: string,
    messageCounter: number
  ): ArrayBuffer | undefined {
    const compositeKey = `${ratchetKeyId}:${messageCounter}`;
    const skippedKey = this.globalSkippedKeys[compositeKey];

    if (skippedKey) {
      delete this.globalSkippedKeys[compositeKey];
      console.log(`Consumed skipped message key: ${compositeKey}`);
      return skippedKey.messageKey;
    }

    return undefined;
  }

  /**
   * Checks if we have a skipped key without consuming it.
   *
   * @param ratchetKeyId Ratchet key identifier
   * @param messageCounter Message counter within the ratchet
   * @returns boolean True if key exists, false otherwise
   */
  public hasSkippedMessageKey(
    ratchetKeyId: string,
    messageCounter: number
  ): boolean {
    const compositeKey = `${ratchetKeyId}:${messageCounter}`;
    return compositeKey in this.globalSkippedKeys;
  }

  /**
   * Gets statistics about skipped keys and ratchet state.
   *
   * @returns Object containing various statistics
   */
  public getSkippedKeyStats() {
    const stats = {
      totalSkippedKeys: Object.keys(this.globalSkippedKeys).length,
      ratchetSteps: this.items.length,
      ratchetKeyIds: Object.keys(this.ratchetKeyLookup).length,
      limits: this.limits,
    };

    return stats;
  }

  /**
   * Cleans up expired skipped keys using configurable TTL.
   */
  private cleanupExpiredSkippedKeys(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [compositeKey, skippedKey] of Object.entries(
      this.globalSkippedKeys
    )) {
      if (now - skippedKey.timestamp > this.limits.skippedKeyTTL) {
        delete this.globalSkippedKeys[compositeKey];
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      console.log(`Cleaned up ${cleanedCount} expired skipped message keys`);
    }
  }

  /**
   * Cleans up skipped keys for a specific ratchet step.
   *
   * @param ratchetKeyId Ratchet key identifier to clean up
   */
  private cleanupSkippedKeysForRatchet(ratchetKeyId: string): void {
    let cleanedCount = 0;

    for (const compositeKey of Object.keys(this.globalSkippedKeys)) {
      if (compositeKey.startsWith(`${ratchetKeyId}:`)) {
        delete this.globalSkippedKeys[compositeKey];
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      console.log(
        `Cleaned up ${cleanedCount} skipped keys for ratchet ${ratchetKeyId}`
      );
    }
  }
}
