/**
 * /src/storage.ts
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

export class AssocStorage<T> {
  protected items: { [key: string]: T } = {};

  public get length() {
    return Object.keys(this.items).length;
  }

  public save(key: string, value: T) {
    this.items[key] = value;
  }

  public load(key: string) {
    return this.items[key];
  }

  public remove(key: string) {
    delete this.items[key];
  }

  public clear() {
    this.items = {};
  }
}
