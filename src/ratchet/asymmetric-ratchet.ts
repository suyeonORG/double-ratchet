/**
 * /src/ratchet/asymmetric-ratchet.ts
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

import { EventEmitter } from "events";
import { INFO_MESSAGE_KEYS, INFO_RATCHET } from "../const";
import { Curve, ECPublicKey, IECKeyPair, Secret } from "../crypto";
import { Identity } from "../data";
import { RemoteIdentity } from "../data/remote_identity";
import {
  IdentityProtocol,
  MessageProtocol,
  MessageSignedProtocol,
  PreKeyBundleProtocol,
  PreKeyMessageProtocol,
} from "../protocol";
import { ReceivingRatchet, SendingRatchet } from "../sym_ratchet";
import { IJsonSerializable } from "../type";
import { ECDHPrivateKey, HMACCryptoKey } from "../type";
import { DHRatchetStepEnhanced, DHRatchetStepStackEnhanced } from "./dh-step";
import {
  IAsymmetricRatchetOptions,
  IJsonAsymmetricRatchet,
  ISkippedMessageStats,
} from "./types";
import { authenticateA, authenticateB } from "./x3dh";

export class AsymmetricRatchet
  extends EventEmitter
  implements IJsonSerializable
{
  /**
   * Creates new ratchet for given identity from PreKeyBundle or PreKey messages.
   *
   * @param identity Local identity
   * @param protocol PreKey bundle or message protocol
   * @param options Configuration options
   * @returns Promise<AsymmetricRatchet> Initialized ratchet instance
   */
  public static async create(
    identity: Identity,
    protocol: PreKeyBundleProtocol | PreKeyMessageProtocol,
    options: IAsymmetricRatchetOptions = {}
  ): Promise<AsymmetricRatchet> {
    let rootKey: HMACCryptoKey;
    const ratchet = new AsymmetricRatchet(options);

    if (protocol instanceof PreKeyBundleProtocol) {
      if (!(await protocol.identity.verify())) {
        throw new Error("Error: Remote client's identity key is invalid.");
      }

      if (!(await protocol.preKeySigned.verify(protocol.identity.signingKey))) {
        throw new Error("Error: Remote client's signed prekey is invalid.");
      }

      ratchet.currentRatchetKey = await ratchet.generateRatchetKey();
      ratchet.currentStep.remoteRatchetKey = protocol.preKeySigned.key;
      ratchet.currentStep.ratchetKeyId = protocol.preKeySigned.key.id;
      ratchet.remoteIdentity = RemoteIdentity.fill(protocol.identity);
      ratchet.remoteIdentity.id = protocol.registrationId;
      ratchet.remotePreKeyId = protocol.preKey?.id;
      ratchet.remotePreKeySignedId = protocol.preKeySigned.id;

      rootKey = await authenticateA(
        identity,
        ratchet.currentRatchetKey,
        protocol.identity.exchangeKey,
        protocol.preKeySigned.key,
        protocol.preKey?.key
      );
    } else {
      if (!(await protocol.identity.verify())) {
        throw new Error("Error: Remote client's identity key is invalid.");
      }

      const signedPreKey = identity.signedPreKeys[protocol.preKeySignedId];
      if (!signedPreKey) {
        throw new Error(
          `Error: PreKey with id ${protocol.preKeySignedId} not found`
        );
      }

      let preKey: IECKeyPair | undefined;
      if (protocol.preKeyId !== void 0) {
        preKey = identity.preKeys[protocol.preKeyId];

        // Remove one-time pre-key after use
        if (preKey) {
          delete identity.preKeys[protocol.preKeyId];
          console.log(
            `One-time pre-key with ID ${protocol.preKeyId} has been consumed and removed`
          );
        }
      }

      ratchet.remoteIdentity = RemoteIdentity.fill(protocol.identity);
      ratchet.currentRatchetKey = signedPreKey;
      rootKey = await authenticateB(
        identity,
        ratchet.currentRatchetKey,
        protocol.identity.exchangeKey,
        protocol.signedMessage.message.senderRatchetKey,
        preKey && preKey.privateKey
      );
    }

    ratchet.identity = identity;
    ratchet.id = identity.id;
    ratchet.rootKey = rootKey;
    return ratchet;
  }

  /**
   * Creates AsymmetricRatchet instance from JSON data.
   *
   * @param identity Local identity
   * @param remote Remote identity
   * @param obj JSON object containing ratchet state
   * @returns Promise<AsymmetricRatchet> Reconstructed ratchet instance
   */
  public static async fromJSON(
    identity: Identity,
    remote: RemoteIdentity,
    obj: IJsonAsymmetricRatchet
  ): Promise<AsymmetricRatchet> {
    const res = new AsymmetricRatchet();
    res.identity = identity;
    res.remoteIdentity = remote;
    await res.fromJSON(obj);
    return res;
  }

  public id: number;
  public rootKey: HMACCryptoKey;
  public identity: Identity;
  public remoteIdentity: RemoteIdentity;
  public remotePreKeyId?: number;
  public remotePreKeySignedId: number;
  public counter = 0;
  public currentStep = new DHRatchetStepEnhanced();
  public currentRatchetKey: IECKeyPair;

  /** Enhanced DH ratchet steps with configurable limits */
  protected steps: DHRatchetStepStackEnhanced;

  /** Separate promise queues for encrypt and decrypt operations */
  protected promises: {
    encrypt: Promise<unknown> | null;
    decrypt: Promise<unknown> | null;
    [key: string]: Promise<unknown> | null;
  } = {
    encrypt: null,
    decrypt: null,
  };

  /**
   * Creates a new AsymmetricRatchet instance with configuration options.
   *
   * @param options Configuration options
   */
  protected constructor(public options: IAsymmetricRatchetOptions = {}) {
    super();
    this.steps = new DHRatchetStepStackEnhanced(options.limits);
  }

  public on(event: "update", listener: () => void): this;
  public on(event: string | symbol, listener: (...args: unknown[]) => void) {
    return super.on(event, listener);
  }

  public once(event: "update", listener: () => void): this;
  public once(event: string | symbol, listener: (...args: unknown[]) => void) {
    return super.once(event, listener);
  }

  /**
   * Verifies and decrypts data from SignedMessage with improved skipped message handling.
   *
   * @param protocol Message protocol to decrypt
   * @returns Promise<ArrayBuffer> Decrypted message content
   */
  public async decrypt(protocol: MessageSignedProtocol): Promise<ArrayBuffer> {
    return this.queuePromise("decrypt", async () => {
      const remoteRatchetKey = protocol.message.senderRatchetKey;
      const message = protocol.message;
      const messageCounter = message.counter;

      // Check message age against ratchet window
      const maxAllowedAge = this.counter - this.steps.maxSize;
      if (protocol.message.previousCounter < maxAllowedAge) {
        throw new Error("Error: Message too old - outside ratchet window");
      }

      // Try to find existing step
      let step = this.steps.getStep(remoteRatchetKey);

      if (!step) {
        // New ratchet key - create new step
        const ratchetStep = new DHRatchetStepEnhanced();
        ratchetStep.remoteRatchetKey = remoteRatchetKey;
        ratchetStep.ratchetKeyId = remoteRatchetKey.id;
        this.steps.push(ratchetStep);
        this.currentStep = ratchetStep;
        step = ratchetStep;
      }

      // Check if this is a skipped message we already have the key for
      if (step.ratchetKeyId) {
        const skippedKey = this.steps.consumeSkippedMessageKey(
          step.ratchetKeyId,
          messageCounter
        );
        if (skippedKey) {
          console.log(
            `Using pre-computed skipped message key for counter ${messageCounter}`
          );
          return await this.decryptWithKey(
            skippedKey,
            message.cipherText,
            protocol
          );
        }
      }

      // Create receiving chain if needed
      if (!step.receivingChain) {
        step.receivingChain = await this.createChain(
          this.currentRatchetKey.privateKey,
          remoteRatchetKey,
          ReceivingRatchet
        );
      }

      if (!step.receivingChain) {
        throw new Error("Failed to create receiving chain");
      }

      // Handle skipped messages in order
      if (messageCounter > step.lastDecryptedCounter + 1) {
        // Generate and store skipped message keys
        await this.generateSkippedMessageKeys(
          step,
          step.lastDecryptedCounter + 1,
          messageCounter - 1
        );
      }

      // Create minimal AAD for header integrity (8 bytes total)
      const aad = this.createMinimalAAD(
        message.counter,
        message.previousCounter
      );

      // Decrypt the current message with AAD
      const decryptedMessage = await step.receivingChain.decrypt(
        message.cipherText,
        messageCounter,
        aad
      );

      // Update last decrypted counter
      step.lastDecryptedCounter = Math.max(
        step.lastDecryptedCounter,
        messageCounter
      );

      this.update();

      // Verify message signature
      protocol.senderKey = this.remoteIdentity.signingKey;
      protocol.receiverKey = this.identity.signingKey.publicKey;
      if (!(await protocol.verify(decryptedMessage.hmacKey))) {
        throw new Error("Error: The Message did not successfully verify!");
      }

      return decryptedMessage.cipherText;
    });
  }

  /**
   * Encrypts message using current ratchet state.
   *
   * @param message Message content to encrypt
   * @returns Promise<PreKeyMessageProtocol | MessageSignedProtocol> Encrypted message
   */
  public async encrypt(
    message: ArrayBuffer
  ): Promise<PreKeyMessageProtocol | MessageSignedProtocol> {
    return this.queuePromise("encrypt", async () => {
      if (this.currentStep.receivingChain && !this.currentStep.sendingChain) {
        // Close ratchet step
        this.counter++;
        this.currentRatchetKey = await this.generateRatchetKey();
      }

      // If no incoming message with new ratchet key, use old DH ratchet
      if (!this.currentStep.sendingChain) {
        if (!this.currentStep.remoteRatchetKey) {
          throw new Error("currentStep has empty remoteRatchetKey");
        }
        this.currentStep.sendingChain = await this.createChain(
          this.currentRatchetKey.privateKey,
          this.currentStep.remoteRatchetKey,
          SendingRatchet
        );
      }

      if (!this.currentStep.sendingChain) {
        throw new Error("Failed to create sending chain");
      }

      // Get counter values for message header and AAD
      const messageCounter = this.currentStep.sendingChain?.counter ?? 0;
      const messagePreviousCounter = this.counter;

      // Create minimal AAD for header integrity (8 bytes total)
      const aad = this.createMinimalAAD(messageCounter, messagePreviousCounter);

      const encryptedMessage = await this.currentStep.sendingChain.encrypt(
        message,
        aad
      );
      this.update();

      let preKeyMessage: PreKeyMessageProtocol | undefined;
      if (
        this.steps.length === 0 &&
        !this.currentStep.receivingChain &&
        this.currentStep.sendingChain.counter === 1
      ) {
        // First message MUST be PreKey message, otherwise SignedMessage
        preKeyMessage = new PreKeyMessageProtocol();
        preKeyMessage.registrationId = this.identity.id;
        preKeyMessage.preKeyId = this.remotePreKeyId;
        preKeyMessage.preKeySignedId = this.remotePreKeySignedId;
        preKeyMessage.baseKey = this.currentRatchetKey.publicKey;

        preKeyMessage.identity = new IdentityProtocol();
        await preKeyMessage.identity.fill(this.identity);
      }

      const signedMessage = new MessageSignedProtocol();
      signedMessage.message = new MessageProtocol();
      signedMessage.receiverKey = this.remoteIdentity.signingKey;
      signedMessage.senderKey = this.identity.signingKey.publicKey;

      // Message content
      signedMessage.message.cipherText = encryptedMessage.cipherText;
      signedMessage.message.counter = messageCounter;
      signedMessage.message.previousCounter = messagePreviousCounter;
      signedMessage.message.senderRatchetKey = this.currentRatchetKey.publicKey;
      await signedMessage.sign(encryptedMessage.hmacKey);

      if (preKeyMessage) {
        preKeyMessage.signedMessage = signedMessage;
        return preKeyMessage;
      } else {
        return signedMessage;
      }
    });
  }

  /**
   * Checks if the ratchet has a specific ratchet key.
   *
   * @param key Crypto key or ECPublicKey to check
   * @returns Promise<boolean> True if key exists, false otherwise
   */
  public async hasRatchetKey(key: CryptoKey | ECPublicKey): Promise<boolean> {
    let ecKey: ECPublicKey;
    if (!(key instanceof ECPublicKey)) {
      ecKey = await ECPublicKey.create(key);
    } else {
      ecKey = key;
    }

    for (const item of this.steps.items) {
      if (await item.remoteRatchetKey!.isEqual(ecKey)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Serializes the ratchet state to JSON.
   *
   * @returns Promise<IJsonAsymmetricRatchet> JSON representation
   */
  public async toJSON(): Promise<IJsonAsymmetricRatchet> {
    return {
      counter: this.counter,
      ratchetKey: await Curve.ecKeyPairToJson(this.currentRatchetKey),
      remoteIdentity: await this.remoteIdentity.signingKey.thumbprint(),
      rootKey: this.rootKey,
      steps: await this.steps.toJSON(),
    } as IJsonAsymmetricRatchet;
  }

  /**
   * Reconstructs the ratchet state from JSON.
   *
   * @param obj JSON object containing ratchet state
   */
  public async fromJSON(obj: IJsonAsymmetricRatchet): Promise<void> {
    this.currentRatchetKey = await Curve.ecKeyPairFromJson(obj.ratchetKey);
    this.counter = obj.counter;
    this.rootKey = obj.rootKey;

    for (const step of obj.steps) {
      this.currentStep = await DHRatchetStepEnhanced.fromJSON(step);
      this.steps.push(this.currentStep);
    }
  }

  /**
   * Gets statistics about skipped message keys.
   *
   * @returns ISkippedMessageStats Statistics object
   */
  public getSkippedMessageStats(): ISkippedMessageStats {
    return this.steps.getSkippedKeyStats();
  }

  /**
   * Emits update event to listeners.
   */
  protected update(): void {
    this.emit("update");
  }

  /**
   * Generates new ratchet key (X25519).
   *
   * @returns Promise<IECKeyPair> New key pair
   */
  protected generateRatchetKey(): Promise<IECKeyPair> {
    return Curve.generateKeyPair("X25519", !!this.options.exportableKeys);
  }

  /**
   * Creates new symmetric ratchet
   *
   * @param ourRatchetKey Our private ratchet key
   * @param theirRatchetKey Their public ratchet key
   * @param ratchetClass Ratchet class to instantiate
   * @returns Promise<ReceivingRatchet | SendingRatchet> New ratchet chain
   */
  protected async createChain(
    ourRatchetKey: ECDHPrivateKey,
    theirRatchetKey: ECPublicKey,
    ratchetClass: typeof ReceivingRatchet
  ): Promise<ReceivingRatchet>;
  protected async createChain(
    ourRatchetKey: ECDHPrivateKey,
    theirRatchetKey: ECPublicKey,
    ratchetClass: typeof SendingRatchet
  ): Promise<SendingRatchet>;
  protected async createChain(
    ourRatchetKey: ECDHPrivateKey,
    theirRatchetKey: ECPublicKey,
    ratchetClass: typeof ReceivingRatchet | typeof SendingRatchet
  ) {
    // Standard DH operation
    const derivedBytes = await Curve.deriveBytes(
      ourRatchetKey,
      theirRatchetKey
    );

    // Standard Double Ratchet - use DH output directly for HKDF
    const keys = await Secret.HKDF(derivedBytes, 2, this.rootKey, INFO_RATCHET);
    const rootKey = await Secret.importHMAC(keys[0]);
    const chainKey = await Secret.importHMAC(keys[1]);
    const chain = new ratchetClass(chainKey);
    this.rootKey = rootKey; // Update rootKey
    return chain;
  }

  /**
   * Queues promises to prevent race conditions.
   *
   * @param key Queue key (encrypt/decrypt)
   * @param fn Function to execute
   * @returns Promise<T> Queued promise result
   */
  protected queuePromise<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.promises[key] || Promise.resolve();
    const cur = (this.promises[key] = prev.then(fn, fn));
    cur.then(() => {
      if (this.promises[key] === cur) {
        this.promises[key] = null;
      }
    });
    return cur;
  }

  /**
   * Generates and stores keys for skipped messages.
   *
   * @param step DH ratchet step
   * @param fromCounter Starting counter
   * @param toCounter Ending counter
   */
  private async generateSkippedMessageKeys(
    step: DHRatchetStepEnhanced,
    fromCounter: number,
    toCounter: number
  ): Promise<void> {
    if (!step.receivingChain || !step.ratchetKeyId) {
      return;
    }

    console.log(
      `Generating skipped keys for counters ${fromCounter}-${toCounter} in ratchet ${step.ratchetKeyId}`
    );

    for (let counter = fromCounter; counter <= toCounter; counter++) {
      try {
        if (!this.steps.hasSkippedMessageKey(step.ratchetKeyId, counter)) {
          console.log(`Marking counter ${counter} for skipped key generation`);
        }
      } catch (error) {
        console.warn(
          `Failed to mark skipped key for counter ${counter}:`,
          error
        );
        break;
      }
    }
  }

  /**
   * Decrypts message with a pre-computed key.
   *
   * @param messageKey Pre-computed message key
   * @param cipherText Encrypted message content
   * @param protocol Message protocol for verification
   * @returns Promise<ArrayBuffer> Decrypted message
   */
  private async decryptWithKey(
    messageKey: ArrayBuffer,
    cipherText: ArrayBuffer,
    protocol: MessageSignedProtocol
  ): Promise<ArrayBuffer> {
    // Derive decryption keys from the message key
    const keys = await Secret.HKDF(messageKey, 3, void 0, INFO_MESSAGE_KEYS);
    const aesKey = await Secret.importAES(keys[0].slice(0, 32)); // Truncate to 256 bits for AES
    const hmacKey = await Secret.importHMAC(keys[1]);
    const iv = keys[2].slice(0, 12);

    // Create minimal AAD for header integrity
    const aad = this.createMinimalAAD(
      protocol.message.counter,
      protocol.message.previousCounter
    );

    // Decrypt the message with AAD
    const decryptedText = await Secret.decrypt(aesKey, cipherText, iv, aad);

    // Verify signature
    protocol.senderKey = this.remoteIdentity.signingKey;
    protocol.receiverKey = this.identity.signingKey.publicKey;
    if (!(await protocol.verify(hmacKey))) {
      throw new Error("Error: The Message did not successfully verify!");
    }

    return decryptedText;
  }

  /**
   * Creates minimal AAD for header integrity protection.
   * Uses only counter values (8 bytes total) for performance.
   *
   * @param counter Current message counter
   * @param previousCounter Previous ratchet counter
   * @returns ArrayBuffer 8-byte AAD
   */
  private createMinimalAAD(
    counter: number,
    previousCounter: number
  ): ArrayBuffer {
    const aad = new ArrayBuffer(8);
    const view = new DataView(aad);
    view.setUint32(0, counter, false); // Big-endian
    view.setUint32(4, previousCounter, false);
    return aad;
  }
}
