import { asciiBytes, concatBytes, utf8Bytes } from "./bytes.js";

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OBJECT_IDENTIFIER: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18
} as const;

export interface DerElement {
  tag: number;
  headerLength: number;
  length: number;
  start: number;
  end: number;
  value: Uint8Array;
  raw: Uint8Array;
}

export function der(tag: number, value: Uint8Array): Uint8Array {
  return concatBytes([new Uint8Array([tag]), encodeLength(value.length), value]);
}

export function sequence(...children: Uint8Array[]): Uint8Array {
  return der(TAG.SEQUENCE, concatBytes(children));
}

export function set(...children: Uint8Array[]): Uint8Array {
  return der(TAG.SET, concatBytes(children));
}

export function explicit(tagNumber: number, value: Uint8Array): Uint8Array {
  return der(0xa0 + tagNumber, value);
}

export function oid(value: string): Uint8Array {
  const parts = value.split(".").map((part) => {
    if (!/^(0|[1-9]\d*)$/.test(part)) {
      throw new Error(`Invalid OID: ${value}`);
    }
    return Number(part);
  });

  if (parts.length < 2) {
    throw new Error(`Invalid OID: ${value}`);
  }

  const [first, second, ...rest] = parts;
  if (first === undefined || second === undefined || first > 2 || second > 39 && first < 2) {
    throw new Error(`Invalid OID: ${value}`);
  }

  const body = [first * 40 + second, ...rest].flatMap(encodeBase128);
  return der(TAG.OBJECT_IDENTIFIER, new Uint8Array(body));
}

export function boolean(value: boolean): Uint8Array {
  return der(TAG.BOOLEAN, new Uint8Array([value ? 0xff : 0x00]));
}

export function integer(value: bigint | number | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array) {
    return der(TAG.INTEGER, normalizeIntegerBytes(value));
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("INTEGER number must be a non-negative safe integer");
    }
    return integer(BigInt(value));
  }

  if (value < 0n) {
    throw new Error("INTEGER bigint must be non-negative");
  }

  if (value === 0n) {
    return der(TAG.INTEGER, new Uint8Array([0]));
  }

  const bytes: number[] = [];
  let current = value;
  while (current > 0n) {
    bytes.unshift(Number(current & 0xffn));
    current >>= 8n;
  }

  return integer(new Uint8Array(bytes));
}

export function bitString(bytes: Uint8Array, unusedBits = 0): Uint8Array {
  if (unusedBits < 0 || unusedBits > 7) {
    throw new Error("BIT STRING unused bits must be between 0 and 7");
  }

  return der(TAG.BIT_STRING, concatBytes([new Uint8Array([unusedBits]), bytes]));
}

export function octetString(bytes: Uint8Array): Uint8Array {
  return der(TAG.OCTET_STRING, bytes);
}

export function utf8String(value: string): Uint8Array {
  return der(TAG.UTF8_STRING, utf8Bytes(value));
}

export function printableString(value: string): Uint8Array {
  if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)) {
    throw new Error("PrintableString contains an unsupported character");
  }

  return der(TAG.PRINTABLE_STRING, asciiBytes(value));
}

export function ia5String(value: string): Uint8Array {
  return der(TAG.IA5_STRING, asciiBytes(value));
}

export function contextPrimitive(tagNumber: number, value: Uint8Array): Uint8Array {
  return der(0x80 + tagNumber, value);
}

export function utcTime(date: Date): Uint8Array {
  const year = date.getUTCFullYear();
  if (year < 1950 || year > 2049) {
    return generalizedTime(date);
  }

  return der(TAG.UTC_TIME, asciiBytes(`${two(year % 100)}${timeTail(date)}`));
}

export function generalizedTime(date: Date): Uint8Array {
  return der(TAG.GENERALIZED_TIME, asciiBytes(`${date.getUTCFullYear()}${timeTail(date)}`));
}

export function readElement(input: Uint8Array, offset = 0): DerElement {
  if (offset >= input.length) {
    throw new Error("Unexpected end of DER input");
  }

  const tag = input[offset]!;
  const lengthInfo = decodeLength(input, offset + 1);
  const start = lengthInfo.offset;
  const end = start + lengthInfo.length;

  if (end > input.length) {
    throw new Error("DER length exceeds input size");
  }

  return {
    tag,
    headerLength: start - offset,
    length: lengthInfo.length,
    start,
    end,
    value: input.subarray(start, end),
    raw: input.subarray(offset, end)
  };
}

export function readSequenceChildren(element: DerElement): DerElement[] {
  if (element.tag !== TAG.SEQUENCE) {
    throw new Error("Expected SEQUENCE");
  }

  return readChildren(element.value);
}

export function readChildren(input: Uint8Array): DerElement[] {
  const out: DerElement[] = [];
  let offset = 0;

  while (offset < input.length) {
    const element = readElement(input, offset);
    out.push(element);
    offset = element.end;
  }

  if (offset !== input.length) {
    throw new Error("Invalid DER children");
  }

  return out;
}

export function decodeOid(input: Uint8Array): string {
  if (input.length === 0) {
    throw new Error("Invalid empty OID");
  }

  const first = input[0]!;
  const parts = first >= 80 ? [2, first - 80] : [Math.floor(first / 40), first % 40];
  let value = 0;

  for (let i = 1; i < input.length; i += 1) {
    const byte = input[i]!;
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }

  if (value !== 0) {
    throw new Error("Truncated OID");
  }

  return parts.join(".");
}

export function decodeInteger(input: Uint8Array): bigint {
  if (input.length === 0) {
    throw new Error("Invalid empty INTEGER");
  }

  if ((input[0]! & 0x80) !== 0) {
    throw new Error("Negative INTEGER is unsupported");
  }

  let value = 0n;
  for (const byte of input) {
    value = (value << 8n) | BigInt(byte);
  }

  return value;
}

function encodeLength(length: number): Uint8Array {
  if (length < 0x80) {
    return new Uint8Array([length]);
  }

  const bytes: number[] = [];
  let current = length;
  while (current > 0) {
    bytes.unshift(current & 0xff);
    current >>= 8;
  }

  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function decodeLength(input: Uint8Array, offset: number): { length: number; offset: number } {
  const first = input[offset];
  if (first === undefined) {
    throw new Error("Missing DER length");
  }

  if ((first & 0x80) === 0) {
    return { length: first, offset: offset + 1 };
  }

  const count = first & 0x7f;
  if (count === 0) {
    throw new Error("Indefinite DER length is not allowed");
  }

  if (offset + 1 + count > input.length) {
    throw new Error("Truncated DER length");
  }

  let length = 0;
  for (let i = 0; i < count; i += 1) {
    length = (length << 8) | input[offset + 1 + i]!;
  }

  return { length, offset: offset + 1 + count };
}

function encodeBase128(value: number): number[] {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("OID component must be a non-negative safe integer");
  }

  if (value === 0) {
    return [0];
  }

  const bytes: number[] = [];
  let current = value;

  while (current > 0) {
    bytes.unshift(current & 0x7f);
    current >>= 7;
  }

  for (let i = 0; i < bytes.length - 1; i += 1) {
    bytes[i] = bytes[i]! | 0x80;
  }

  return bytes;
}

function normalizeIntegerBytes(bytes: Uint8Array): Uint8Array {
  let offset = 0;
  while (offset < bytes.length - 1 && bytes[offset] === 0) {
    offset += 1;
  }

  const trimmed = bytes.subarray(offset);
  if (trimmed.length === 0) {
    return new Uint8Array([0]);
  }

  if ((trimmed[0]! & 0x80) !== 0) {
    return concatBytes([new Uint8Array([0]), trimmed]);
  }

  return new Uint8Array(trimmed);
}

function timeTail(date: Date): string {
  return `${two(date.getUTCMonth() + 1)}${two(date.getUTCDate())}${two(date.getUTCHours())}${two(date.getUTCMinutes())}${two(date.getUTCSeconds())}Z`;
}

function two(value: number): string {
  return value.toString().padStart(2, "0");
}
