/**
 * /src/protocol/prekey_signed.ts
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
import { PreKeyProtocol } from "./prekey";
import {
  ArrayBufferConverter,
  ProtobufElement,
  ProtobufProperty,
} from "./serialization";

@ProtobufElement({ name: "PreKeySigned" })
export class PreKeySignedProtocol extends PreKeyProtocol {
  @ProtobufProperty({ id: 3, converter: ArrayBufferConverter, required: true })
  public signature: ArrayBuffer;

  public async sign(key: CryptoKey) {
    this.signature = await Curve.sign(key, this.key.serialize());
  }

  public verify(key: ECPublicKey) {
    return Curve.verify(key, this.key.serialize(), this.signature);
  }
}
