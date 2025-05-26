/**
 * /src/stack.ts
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
import { IJsonSerializable } from "./type";

export class Stack<T extends IJsonSerializable> implements IJsonSerializable {
  public items: T[] = [];

  public maxSize: number;

  get length() {
    return this.items.length;
  }

  get latest() {
    return this.items[this.length - 1];
  }

  constructor(maxSize = 20) {
    this.maxSize = maxSize;
  }

  public push(item: T) {
    if (this.length === this.maxSize) {
      this.items = this.items.slice(1);
    }
    this.items.push(item);
  }

  public async toJSON() {
    const res = [];
    for (const item of this.items) {
      res.push(await item.toJSON());
    }
    return res;
  }

  public async fromJSON(obj: T[]) {
    this.items = obj;
  }
}
