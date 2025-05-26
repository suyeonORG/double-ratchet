/**
 * /src/protocol/prekey_bundle.ts
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

import { BaseProtocol } from "./base";
import { IdentityProtocol } from "./identity";
import { PreKeyProtocol } from "./prekey";
import { PreKeySignedProtocol } from "./prekey_signed";
import { ProtobufElement, ProtobufProperty } from "./serialization";

@ProtobufElement({ name: "PreKeyBundle" })
export class PreKeyBundleProtocol extends BaseProtocol {
  @ProtobufProperty({ id: 1, type: "uint32", required: true })
  public registrationId: number;

  @ProtobufProperty({ id: 2, parser: IdentityProtocol, required: true })
  public identity: IdentityProtocol;

  @ProtobufProperty({ id: 3, parser: PreKeyProtocol })
  public preKey: PreKeyProtocol;

  @ProtobufProperty({ id: 4, parser: PreKeySignedProtocol, required: true })
  public preKeySigned: PreKeySignedProtocol;
}
