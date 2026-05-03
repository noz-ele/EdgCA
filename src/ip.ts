export function encodeIpAddress(value: string): Uint8Array {
  return value.includes(":") ? encodeIpv6(value) : encodeIpv4(value);
}

function encodeIpv4(value: string): Uint8Array {
  const parts = value.split(".");
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address: ${value}`);
  }

  return new Uint8Array(
    parts.map((part) => {
      if (!/^(0|[1-9]\d*)$/.test(part)) {
        throw new Error(`Invalid IPv4 address: ${value}`);
      }
      const octet = Number(part);
      if (octet < 0 || octet > 255) {
        throw new Error(`Invalid IPv4 address: ${value}`);
      }
      return octet;
    })
  );
}

function encodeIpv6(value: string): Uint8Array {
  if (value.split("::").length > 2) {
    throw new Error(`Invalid IPv6 address: ${value}`);
  }

  const [leftPart = "", rightPart = ""] = value.split("::");
  const left = parseIpv6Groups(leftPart, value);
  const right = parseIpv6Groups(rightPart, value);
  const missing = 8 - left.length - right.length;

  if (value.includes("::")) {
    if (missing < 1) {
      throw new Error(`Invalid IPv6 address: ${value}`);
    }
  } else if (missing !== 0) {
    throw new Error(`Invalid IPv6 address: ${value}`);
  }

  const groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  const out = new Uint8Array(16);

  groups.forEach((group, index) => {
    out[index * 2] = group >> 8;
    out[index * 2 + 1] = group & 0xff;
  });

  return out;
}

function parseIpv6Groups(part: string, original: string): number[] {
  if (part === "") {
    return [];
  }

  return part.split(":").map((group) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
      throw new Error(`Invalid IPv6 address: ${original}`);
    }
    return Number.parseInt(group, 16);
  });
}
