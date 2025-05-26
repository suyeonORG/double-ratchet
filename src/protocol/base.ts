/**
 * /src/protocol/base.ts
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

import {
  ObjectProto,
  ProtobufElement,
  ProtobufProperty,
} from "./serialization";

@ProtobufElement({ name: "Base" })
export class BaseProtocol extends ObjectProto {
  @ProtobufProperty({ id: 0, type: "uint32", defaultValue: 1 })
  public version: number;
}
