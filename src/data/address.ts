/**
 * /src/data/address.ts
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

export class Address {
  protected static readonly SPLITTER = ":";

  public name: string;
  public id: number;

  constructor(name: string, id: number) {
    this.id = id;
    this.name = name;
  }

  public toString() {
    return `${this.name}${Address.SPLITTER}${this.id}`;
  }
}
