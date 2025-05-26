/**
 * /src/protocol/prekey_message.ts
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

import { ECPublicKey } from "../crypto/public_key";
import { BaseProtocol } from "./base";
import { ECDHPublicKeyConverter } from "./converter";
import { IdentityProtocol } from "./identity";
import { MessageSignedProtocol } from "./message_signed";
import { ProtobufElement, ProtobufProperty } from "./serialization";

@ProtobufElement({ name: "PreKeyMessage" })
export class PreKeyMessageProtocol extends BaseProtocol {
  @ProtobufProperty({ id: 1, type: "uint32", required: true })
  public registrationId: number;

  @ProtobufProperty({ id: 2, type: "uint32" })
  public preKeyId?: number;

  @ProtobufProperty({ id: 3, type: "uint32", required: true })
  public preKeySignedId: number;

  @ProtobufProperty({
    id: 4,
    converter: ECDHPublicKeyConverter,
    required: true,
  })
  public baseKey: ECPublicKey;

  @ProtobufProperty({ id: 5, parser: IdentityProtocol, required: true })
  public identity: IdentityProtocol;

  @ProtobufProperty({ id: 6, parser: MessageSignedProtocol, required: true })
  public signedMessage: MessageSignedProtocol;
}
