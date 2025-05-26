/**
 * /src/protocol/message_signed.ts
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

import { ECPublicKey, Secret } from "../crypto";
import { combine, isEqual } from "../utils";
import { BaseProtocol } from "./base";
import { ECDSAPublicKeyConverter } from "./converter";
import { MessageProtocol } from "./message";
import { ProtobufElement, ProtobufProperty } from "./serialization";

@ProtobufElement({ name: "MessageSigned" })
export class MessageSignedProtocol extends BaseProtocol {
  public receiverKey: ECPublicKey;

  @ProtobufProperty({
    id: 1,
    converter: ECDSAPublicKeyConverter,
    required: true,
  })
  public senderKey: ECPublicKey;

  @ProtobufProperty({ id: 2, parser: MessageProtocol, required: true })
  public message: MessageProtocol;

  @ProtobufProperty({ id: 3, required: true })
  protected signature: ArrayBuffer;

  public async sign(hmacKey: CryptoKey) {
    this.signature = await this.signHMAC(hmacKey);
  }

  public async verify(hmacKey: CryptoKey) {
    const signature = await this.signHMAC(hmacKey);
    return isEqual(signature, this.signature);
  }

  protected async getSignedRaw() {
    const receiverKey = this.receiverKey.serialize();
    const senderKey = this.senderKey.serialize();
    const message = await this.message.exportProto();

    const data = combine(receiverKey, senderKey, message);
    return data;
  }

  protected async signHMAC(macKey: CryptoKey) {
    const data = await this.getSignedRaw();

    const signature = await Secret.sign(macKey, data);
    return signature;
  }
}
