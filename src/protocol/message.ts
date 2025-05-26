/**
 * /src/protocol/message.ts
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

import { ECPublicKey } from "../crypto";
import { BaseProtocol } from "./base";
import { ECDHPublicKeyConverter } from "./converter";
import {
  ArrayBufferConverter,
  ProtobufElement,
  ProtobufProperty,
} from "./serialization";

@ProtobufElement({ name: "Message" })
export class MessageProtocol extends BaseProtocol {
  @ProtobufProperty({
    id: 1,
    converter: ECDHPublicKeyConverter,
    required: true,
  })
  public senderRatchetKey: ECPublicKey;

  @ProtobufProperty({ id: 2, type: "uint32", required: true })
  public counter: number;

  @ProtobufProperty({ id: 3, type: "uint32", required: true })
  public previousCounter: number;

  @ProtobufProperty({ id: 4, converter: ArrayBufferConverter, required: true })
  public cipherText: ArrayBuffer;
}
