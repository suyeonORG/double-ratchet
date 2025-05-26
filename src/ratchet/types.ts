/**
 * /src/ratchet/types.ts
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

import { IRatchetLimits } from "../const";
import { IJsonReceivingRatchet, IJsonSymmetricRatchet } from "../sym_ratchet";

export interface ISkippedMessageKey {
  /** DH ratchet key thumbprint for identification */
  ratchetKeyId: string;
  /** Message counter within that DH step */
  messageCounter: number;
  /** The actual message key for decryption */
  messageKey: ArrayBuffer;
  /** Timestamp when this key was generated (for TTL cleanup) */
  timestamp: number;
}

export interface IJsonDHRatchetStepEnhanced {
  /** Remote party's ratchet public key */
  remoteRatchetKey?: CryptoKey;
  /** Sending chain for this DH step */
  sendingChain?: IJsonSymmetricRatchet;
  /** Receiving chain for this DH step */
  receivingChain?: IJsonReceivingRatchet;
  /** Thumbprint of the remote ratchet key for identification */
  ratchetKeyId?: string;
  /** Last successfully decrypted message counter */
  lastDecryptedCounter?: number;
  /** Skipped message keys, keyed by messageCounter for O(1) lookup */
  skippedMessageKeys?: { [key: string]: ArrayBuffer };
}

/**
 * JSON serialization interface for the entire AsymmetricRatchet state.
 */
export interface IJsonAsymmetricRatchet {
  /** Serialized remote identity */
  remoteIdentity: string;
  /** Current DH ratchet key pair */
  ratchetKey: CryptoKeyPair;
  /** Current ratchet counter */
  counter: number;
  /** Root key for DH ratchet */
  rootKey: CryptoKey;
  /** Array of DH ratchet steps */
  steps: IJsonDHRatchetStepEnhanced[];
}

/**
 * Configuration options for AsymmetricRatchet instances.
 */
export interface IAsymmetricRatchetOptions {
  /** Whether generated keys should be exportable */
  exportableKeys?: boolean;
  /** Enable debug logging */
  debug?: boolean;
  /** Configurable limits for DoS protection */
  limits?: IRatchetLimits;
}

/**
 * Statistics interface for skipped message tracking.
 */
export interface ISkippedMessageStats {
  /** Total number of skipped keys stored */
  totalSkippedKeys: number;
  /** Number of DH ratchet steps with skipped keys */
  ratchetSteps: number;
  /** Number of unique ratchet key IDs with skipped keys */
  ratchetKeyIds: number;
}

/**
 * Legacy compatibility interface for DHRatchetStep.
 * @deprecated Use IJsonDHRatchetStepEnhanced instead
 */
export interface IJsonDHRatchetStep extends IJsonDHRatchetStepEnhanced {}
