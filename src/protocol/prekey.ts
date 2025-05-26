/**
 * /src/protocol/prekey.ts
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
import { ProtobufElement, ProtobufProperty } from "./serialization";

@ProtobufElement({ name: "PreKey" })
export class PreKeyProtocol extends BaseProtocol {
  @ProtobufProperty({ id: 1, type: "uint32", required: true })
  public id: number;

  @ProtobufProperty({
    id: 2,
    converter: ECDHPublicKeyConverter,
    required: true,
  })
  public key: ECPublicKey;
}
