// The part of CBOR (RFC 8949) that WebAuthn uses (docs/DESIGN.md §9.1):
// integers, byte and text strings, arrays and maps of definite length, and
// false, true and null. Tags, floats, indefinite lengths, duplicate map keys
// and integers beyond 2^53 are refused, so every value has one reading.

export type Cbor = number | string | boolean | null | Uint8Array | Cbor[] | Map<number | string, Cbor>;

export class CborError extends Error {
  override name = "CborError";
}

const MAX_DEPTH = 8;

// One item from the start of `bytes`, and the offset just past it. Whatever
// follows is the caller's to read or refuse.
export function decodeCborPrefix(bytes: Uint8Array): { value: Cbor; end: number } {
  const r = new Reader(bytes);
  const value = r.item(0);
  return { value, end: r.at };
}

// Exactly one item, with nothing after it.
export function decodeCbor(bytes: Uint8Array): Cbor {
  const { value, end } = decodeCborPrefix(bytes);
  if (end !== bytes.length) throw new CborError("trailing bytes");
  return value;
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

class Reader {
  at = 0;
  constructor(readonly bytes: Uint8Array) {}

  private take(n: number): Uint8Array {
    if (n > this.bytes.length - this.at) throw new CborError("truncated");
    const out = this.bytes.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }

  // The argument of a head: the value itself, or a length or count.
  private argument(info: number): number {
    if (info < 24) return info;
    if (info > 27) throw new CborError("indefinite or reserved length");
    const b = this.take(1 << (info - 24));
    let n = 0;
    for (const byte of b) n = n * 256 + byte;
    if (n > Number.MAX_SAFE_INTEGER) throw new CborError("integer too large");
    return n;
  }

  item(depth: number): Cbor {
    if (depth > MAX_DEPTH) throw new CborError("nested too deeply");
    const head = this.take(1)[0]!;
    const major = head >> 5;
    const info = head & 31;
    switch (major) {
      case 0:
        return this.argument(info);
      case 1:
        return -1 - this.argument(info);
      case 2:
        return this.take(this.argument(info)).slice();
      case 3:
        try {
          return utf8.decode(this.take(this.argument(info)));
        } catch (e) {
          throw e instanceof CborError ? e : new CborError("invalid UTF-8");
        }
      // A count larger than what is left fails at the first missing item:
      // every item takes at least one byte.
      case 4: {
        const n = this.argument(info);
        const out: Cbor[] = [];
        for (let i = 0; i < n; i++) out.push(this.item(depth + 1));
        return out;
      }
      case 5: {
        const n = this.argument(info);
        const out = new Map<number | string, Cbor>();
        for (let i = 0; i < n; i++) {
          const key = this.item(depth + 1);
          if (typeof key !== "number" && typeof key !== "string") throw new CborError("map key is not an integer or text");
          if (out.has(key)) throw new CborError("duplicate map key");
          out.set(key, this.item(depth + 1));
        }
        return out;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new CborError("unsupported simple value or float");
      default:
        throw new CborError("tags are not supported");
    }
  }
}
