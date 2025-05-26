/**
 * /src/data/remote_identity.ts
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
import { Curve, ECPublicKey } from "../crypto";
import { IdentityProtocol } from "../protocol";
import { IJsonSerializable } from "../type";

export interface IJsonRemoteIdentity {
  id: number;
  /**
   * Thumbprint of signing key
   *
   * @type {string}
   * @memberOf IJsonRemoteIdentity
   */
  thumbprint: string;
  signingKey: CryptoKey;
  exchangeKey: CryptoKey;
  signature: ArrayBuffer;
  createdAt: string;
}

export class RemoteIdentity implements IJsonSerializable {
  public static fill(protocol: IdentityProtocol) {
    const res = new RemoteIdentity();
    res.fill(protocol);
    return res;
  }

  public static async fromJSON(obj: IJsonRemoteIdentity) {
    const res = new this();
    await res.fromJSON(obj);
    return res;
  }

  public id: number;
  public signingKey: ECPublicKey;
  public exchangeKey: ECPublicKey;
  public signature: ArrayBuffer;
  public createdAt: Date;

  public fill(protocol: IdentityProtocol) {
    this.signingKey = protocol.signingKey;
    this.exchangeKey = protocol.exchangeKey;
    this.signature = protocol.signature;
    this.createdAt = protocol.createdAt;
  }

  public verify() {
    return Curve.verify(
      this.signingKey,
      this.exchangeKey.serialize(),
      this.signature
    );
  }

  public async toJSON() {
    return {
      createdAt: this.createdAt.toISOString(),
      exchangeKey: await this.exchangeKey.key,
      id: this.id,
      signature: this.signature,
      signingKey: await this.signingKey.key,
      thumbprint: await this.signingKey.thumbprint(),
    } as IJsonRemoteIdentity;
  }

  public async fromJSON(obj: IJsonRemoteIdentity) {
    this.id = obj.id;
    this.signature = obj.signature;
    this.signingKey = await ECPublicKey.create(obj.signingKey);
    this.exchangeKey = await ECPublicKey.create(obj.exchangeKey);
    this.createdAt = new Date(obj.createdAt);

    const ok = await this.verify();
    if (!ok) {
      throw new Error("Error: Wrong signature for RemoteIdentity");
    }
  }
}
