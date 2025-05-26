/**
 * /src/const.ts
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
import { Convert } from "./utils";
export const SIGN_ALGORITHM_NAME = "Ed25519";
export const DH_ALGORITHM_NAME = "X25519";

// Cryptographic algorithm names
export const SECRET_KEY_NAME = "AES-GCM";
export const HASH_NAME = "SHA-256";
export const HMAC_NAME = "HMAC";

// Instead, use configurable limits that align with Signal's recommendations
export const DEFAULT_MAX_RATCHET_STEPS = 1000; // Much larger, configurable
export const DEFAULT_MAX_SKIPPED_KEYS = 10000; // Per Signal recommendations
export const DEFAULT_SKIPPED_KEY_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
export const DEFAULT_MAX_MESSAGE_KEYS_PER_STEP = 1000; // Per DH step

// Protocol info strings - Signal specification
export const INFO_TEXT = Convert.FromBinary("Signal_X3DH");
export const INFO_RATCHET = Convert.FromBinary("WhisperRatchet");
export const INFO_MESSAGE_KEYS = Convert.FromBinary("WhisperMessageKeys");

// X3DH Protocol Constants
export const X3DH_INFO_TEXT = "Signal_X3DH";
export const X3DH_SALT_LENGTH = 32;
export const X3DH_FILL_BYTE = 0xff;

// Configuration interface for ratchet limits
export interface IRatchetLimits {
  maxRatchetSteps?: number;
  maxSkippedKeys?: number;
  skippedKeyTTL?: number;
  maxMessageKeysPerStep?: number;
}

// Default configuration following Signal spec recommendations
export const DEFAULT_RATCHET_LIMITS: Required<IRatchetLimits> = {
  maxRatchetSteps: DEFAULT_MAX_RATCHET_STEPS,
  maxSkippedKeys: DEFAULT_MAX_SKIPPED_KEYS,
  skippedKeyTTL: DEFAULT_SKIPPED_KEY_TTL,
  maxMessageKeysPerStep: DEFAULT_MAX_MESSAGE_KEYS_PER_STEP,
};
