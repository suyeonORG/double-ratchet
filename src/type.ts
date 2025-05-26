/**
 * /src/type.ts
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
import { IECKeyPair } from "./crypto/key_pair";

export type Ed25519PublicKey = CryptoKey;
export type Ed25519PrivateKey = CryptoKey;
export type X25519PublicKey = CryptoKey;
export type X25519PrivateKey = CryptoKey;

export type ECDHPublicKey = X25519PublicKey;
export type ECDHPrivateKey = X25519PrivateKey;

export type ECDSAPublicKey = Ed25519PublicKey;
export type ECDSAPrivateKey = Ed25519PrivateKey;

export type RatchetKey = X25519PublicKey;
export type RatchetKeyPair = CryptoKeyPair;
export type HMACCryptoKey = CryptoKey;

export type ECKeyType = "Ed25519" | "X25519";

export interface IDHRatchetItem {
  key: RatchetKeyPair;
}

export interface Identity {
  /**
   * remote client's string identity
   */
  id: string;
  /**
   * Remote client's signing key (Ed25519)
   */
  key: Ed25519PublicKey;
}

export interface ISession {
  identityId: string;
}

export interface ISymmetricKDFResult2 {
  rootKey: CryptoKey;
  bytes: Uint8Array;
}

export interface ISymmetricKDFResult {
  cipher: ArrayBuffer;
  rootKey: CryptoKey;
}

export interface IMessageProtocol {
  ratchetKey: X25519PublicKey;
  message: ArrayBuffer;
  counter: number;
}

export interface IIdentityKeyPair {
  signingKey: IECKeyPair; // Ed25519 key pair
  exchangeKey: IECKeyPair; // X25519 key pair
  signature: ArrayBuffer;
}

export interface IPreKeyPair {
  id: number;
  key: IECKeyPair; // X25519 key pair for DH
}

export interface IPreKeySignedPair extends IPreKeyPair {
  signature: ArrayBuffer; // Ed25519 signature
}

export interface IJsonSerializable {
  toJSON(): Promise<any>;
  fromJSON(obj: any): Promise<void>;
}
