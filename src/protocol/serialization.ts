/**
 * /src/protocol/serialization.ts
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

import { combine } from "../utils";

export type PropertyType = "uint32" | "string" | "bytes" | "object" | "date";

export interface PropertyDescriptor {
  id: number;
  type?: PropertyType;
  required?: boolean;
  defaultValue?: unknown;
  converter?: unknown;
  parser?: unknown;
}

export interface ElementDescriptor {
  name: string;
}

const propertyMetadata = new WeakMap<object, Map<string, PropertyDescriptor>>();
const elementMetadata = new WeakMap<object, ElementDescriptor>();

/**
 * Decorator for protocol elements
 */
export function ProtobufElement(descriptor: ElementDescriptor) {
  return function <T extends new (...args: unknown[]) => object>(
    constructor: T
  ) {
    elementMetadata.set(constructor.prototype, descriptor);
    return constructor;
  };
}

/**
 * Decorator for protocol properties
 */
export function ProtobufProperty(descriptor: PropertyDescriptor) {
  return function (target: object, propertyKey: string) {
    if (!propertyMetadata.has(target)) {
      propertyMetadata.set(target, new Map());
    }
    propertyMetadata.get(target)!.set(propertyKey, descriptor);
  };
}

/**
 * Base class for protocol objects
 */
export class ObjectProto {
  /**
   * Serializes the object to binary format
   */
  public async exportProto(): Promise<ArrayBuffer> {
    const metadata = this.getAllMetadata();
    if (metadata.size === 0) {
      throw new Error(
        `No metadata found for serialization of ${this.constructor.name}`
      );
    }

    const chunks: ArrayBuffer[] = [];

    // Sort by field ID for consistent serialization
    const sortedEntries = Array.from(metadata.entries()).sort(
      (a, b) => a[1].id - b[1].id
    );

    for (const [propertyKey, descriptor] of sortedEntries) {
      const value = (this as Record<string, unknown>)[propertyKey];

      if (value === undefined || value === null) {
        if (descriptor.required) {
          throw new Error(
            `Required property ${propertyKey} is undefined in ${this.constructor.name}`
          );
        }
        continue; // Skip undefined optional properties
      }

      // Serialize field ID as 4-byte little-endian
      const fieldHeader = new ArrayBuffer(4);
      const headerView = new DataView(fieldHeader);
      headerView.setUint32(0, descriptor.id, true);

      let serializedValue: ArrayBuffer;

      try {
        // Handle different types and converters
        if (descriptor.converter) {
          const convertedValue = await (
            descriptor.converter as {
              set: (value: unknown) => Promise<ArrayBuffer>;
            }
          ).set(value);
          serializedValue = this.serializeBytes(new Uint8Array(convertedValue));
        } else if (descriptor.parser) {
          if (
            typeof (value as { exportProto?: () => Promise<ArrayBuffer> })
              .exportProto !== "function"
          ) {
            throw new Error(
              `Property ${propertyKey} does not have exportProto method`
            );
          }
          const nestedData = await (
            value as { exportProto: () => Promise<ArrayBuffer> }
          ).exportProto();
          serializedValue = this.serializeBytes(new Uint8Array(nestedData));
        } else {
          switch (descriptor.type) {
            case "uint32":
              serializedValue = this.serializeUint32(value as number);
              break;
            case "string":
              serializedValue = this.serializeString(value as string);
              break;
            case "bytes":
              serializedValue = this.serializeBytes(
                new Uint8Array(value as ArrayBuffer)
              );
              break;
            case "date":
              serializedValue = this.serializeString(
                (value as Date).toISOString()
              );
              break;
            default:
              serializedValue = this.serializeBytes(
                new Uint8Array(value as ArrayBuffer)
              );
          }
        }

        // Add length prefix as 4-byte little-endian
        const lengthPrefix = new ArrayBuffer(4);
        const lengthView = new DataView(lengthPrefix);
        lengthView.setUint32(0, serializedValue.byteLength, true);

        chunks.push(fieldHeader, lengthPrefix, serializedValue);
      } catch (error) {
        throw new Error(
          `Failed to serialize property ${propertyKey}: ${error}`
        );
      }
    }

    return combine(...chunks);
  }

  /**
   * Deserializes the object from binary format
   */
  public async importProto(data: ArrayBuffer): Promise<void> {
    const metadata = this.getAllMetadata();
    if (metadata.size === 0) {
      throw new Error(
        `No metadata found for deserialization of ${this.constructor.name}`
      );
    }

    const view = new DataView(data);
    let offset = 0;

    const seenProperties = new Set<string>();

    while (offset < data.byteLength) {
      if (offset + 8 > data.byteLength) {
        throw new Error(
          `Invalid data: not enough bytes for field header at offset ${offset}`
        );
      }

      // Read field ID (4 bytes little-endian)
      const fieldId = view.getUint32(offset, true);
      offset += 4;

      // Read length (4 bytes little-endian)
      const length = view.getUint32(offset, true);
      offset += 4;

      if (offset + length > data.byteLength) {
        throw new Error(
          `Invalid data: field ${fieldId} length ${length} exceeds remaining data`
        );
      }

      const valueBuffer = data.slice(offset, offset + length);
      offset += length;

      let targetPropertyKey: string | undefined;
      let targetDescriptor: PropertyDescriptor | undefined;

      for (const [propertyKey, descriptor] of metadata.entries()) {
        if (descriptor.id === fieldId) {
          targetPropertyKey = propertyKey;
          targetDescriptor = descriptor;
          break;
        }
      }

      if (!targetPropertyKey || !targetDescriptor) {
        console.warn(
          `Unknown field ID ${fieldId} in ${this.constructor.name}, skipping`
        );
        continue;
      }

      seenProperties.add(targetPropertyKey);

      let deserializedValue: unknown;

      try {
        if (targetDescriptor.converter) {
          const bytes = new Uint8Array(valueBuffer);
          deserializedValue = await (
            targetDescriptor.converter as {
              get: (bytes: Uint8Array) => Promise<unknown>;
            }
          ).get(bytes);
        } else if (targetDescriptor.parser) {
          const nestedObject = new (targetDescriptor.parser as new () => {
            importProto: (buffer: ArrayBuffer) => Promise<void>;
          })();
          if (typeof nestedObject.importProto !== "function") {
            throw new Error(
              `Parser ${
                (targetDescriptor.parser as { name: string }).name
              } does not have importProto method`
            );
          }
          await nestedObject.importProto(valueBuffer);
          deserializedValue = nestedObject;
        } else {
          switch (targetDescriptor.type) {
            case "uint32":
              deserializedValue = this.deserializeUint32(valueBuffer);
              break;
            case "string":
              deserializedValue = this.deserializeString(valueBuffer);
              break;
            case "bytes":
              deserializedValue = valueBuffer;
              break;
            case "date":
              const dateString = this.deserializeString(valueBuffer);
              deserializedValue = new Date(dateString);
              break;
            default:
              deserializedValue = valueBuffer;
          }
        }

        (this as Record<string, unknown>)[targetPropertyKey] =
          deserializedValue;
      } catch (error) {
        throw new Error(
          `Failed to deserialize property ${targetPropertyKey}: ${error}`
        );
      }
    }

    for (const [propertyKey, descriptor] of metadata.entries()) {
      if (descriptor.required && !seenProperties.has(propertyKey)) {
        if (descriptor.defaultValue !== undefined) {
          (this as Record<string, unknown>)[propertyKey] =
            descriptor.defaultValue;
        } else {
          throw new Error(
            `Required property ${propertyKey} not found in ${this.constructor.name}`
          );
        }
      }
    }
  }
  /**
   * Get all metadata including from parent classes
   */
  private getAllMetadata(): Map<string, PropertyDescriptor> {
    const allMetadata = new Map<string, PropertyDescriptor>();

    // Walk up the prototype chain to collect all metadata
    let currentProto = Object.getPrototypeOf(this);
    while (currentProto && currentProto !== Object.prototype) {
      const metadata = propertyMetadata.get(currentProto);
      if (metadata) {
        for (const [key, descriptor] of metadata.entries()) {
          if (!allMetadata.has(key)) {
            allMetadata.set(key, descriptor);
          }
        }
      }
      currentProto = Object.getPrototypeOf(currentProto);
    }

    return allMetadata;
  }

  private serializeUint32(value: number): ArrayBuffer {
    const buffer = new ArrayBuffer(4);
    const view = new DataView(buffer);
    view.setUint32(0, value, true);
    return buffer;
  }

  private deserializeUint32(buffer: ArrayBuffer): number {
    if (buffer.byteLength !== 4) {
      throw new Error(`Expected 4 bytes for uint32, got ${buffer.byteLength}`);
    }
    const view = new DataView(buffer);
    return view.getUint32(0, true);
  }

  private serializeString(value: string): ArrayBuffer {
    const encoder = new TextEncoder();
    return encoder.encode(value).buffer;
  }

  private deserializeString(buffer: ArrayBuffer): string {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
  }

  private serializeBytes(value: Uint8Array): ArrayBuffer {
    return value.buffer.slice(
      value.byteOffset,
      value.byteOffset + value.byteLength
    );
  }
}

/**
 * ArrayBuffer converter for compatibility
 */
export class ArrayBufferConverter {
  public static async set(value: ArrayBuffer): Promise<Uint8Array> {
    return new Uint8Array(value);
  }

  public static async get(value: Uint8Array): Promise<ArrayBuffer> {
    return value.buffer.slice(
      value.byteOffset,
      value.byteOffset + value.byteLength
    );
  }
}
