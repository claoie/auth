import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { base64url, random, sha256 } from "../crypto";

// A software authenticator and the browser in front of it, for tests. It
// answers the options auth issues with what PublicKeyCredential.toJSON()
// gives, and each field can be changed to make the response a check must
// refuse. Not shipped: the image build removes src/testing.

export type CborValue = number | string | boolean | null | Uint8Array | CborValue[] | Map<number | string, CborValue>;

function head(major: number, n: number): number[] {
  const m = major << 5;
  if (n < 24) return [m | n];
  if (n < 0x100) return [m | 24, n];
  if (n < 0x10000) return [m | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) return [m | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return [m | 27, ...b];
}

export function encodeCbor(v: CborValue): Uint8Array {
  const out: number[] = [];
  const put = (x: CborValue): void => {
    if (x === false) out.push(0xf4);
    else if (x === true) out.push(0xf5);
    else if (x === null) out.push(0xf6);
    else if (typeof x === "number") out.push(...(x >= 0 ? head(0, x) : head(1, -1 - x)));
    else if (typeof x === "string") {
      const b = new TextEncoder().encode(x);
      out.push(...head(3, b.length), ...b);
    } else if (x instanceof Uint8Array) out.push(...head(2, x.length), ...x);
    else if (Array.isArray(x)) {
      out.push(...head(4, x.length));
      x.forEach(put);
    } else {
      out.push(...head(5, x.size));
      for (const [k, val] of x) {
        put(k);
        put(val);
      }
    }
  };
  put(v);
  return Uint8Array.from(out);
}

export const UP = 0x01;
export const UV = 0x04;
export const BE = 0x08;
export const BS = 0x10;
export const AT = 0x40;
export const ED = 0x80;

export type Algorithm = -7 | -8 | -257;

// What a test can change in one response.
export interface Edits {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
  rpId?: string;
  flags?: number;
  counter?: number;
  id?: string;
  credentialId?: Uint8Array;
  publicKey?: Uint8Array; // COSE_Key bytes in place of the real one
  afterKey?: Uint8Array; // bytes appended to the attested credential data
  fmt?: string;
  attStmt?: Map<string, CborValue>;
  attestationObject?: (fields: Map<string, CborValue>) => Uint8Array;
  signWith?: KeyObject;
  authenticatorData?: (signed: Buffer) => Buffer; // changes it after signing
}

export interface CreationOptions {
  challenge: string;
  rp: { id: string };
  pubKeyCredParams: { alg: number }[];
}

export interface RequestOptions {
  challenge: string;
  rpId: string;
}

export class SoftAuthenticator {
  readonly credentialId: Buffer;
  readonly privateKey: KeyObject;
  readonly cose: Uint8Array;
  // A synced passkey always reports 0; a security key counts.
  counter: number;

  constructor(
    readonly alg: Algorithm = -7,
    opts: { counts?: boolean; rsaBits?: number } = {},
  ) {
    this.credentialId = random(16);
    this.counter = opts.counts ? 1 : 0;
    if (alg === -7) {
      const k = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const jwk = k.publicKey.export({ format: "jwk" }) as { x: string; y: string };
      this.privateKey = k.privateKey;
      this.cose = encodeCbor(new Map<number, CborValue>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
    } else if (alg === -8) {
      const k = generateKeyPairSync("ed25519");
      const jwk = k.publicKey.export({ format: "jwk" }) as { x: string };
      this.privateKey = k.privateKey;
      this.cose = encodeCbor(new Map<number, CborValue>([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(jwk.x, "base64url")]]));
    } else {
      const k = generateKeyPairSync("rsa", { modulusLength: opts.rsaBits ?? 2048 });
      const jwk = k.publicKey.export({ format: "jwk" }) as { n: string; e: string };
      this.privateKey = k.privateKey;
      this.cose = encodeCbor(new Map<number, CborValue>([[1, 3], [3, -257], [-1, Buffer.from(jwk.n, "base64url")], [-2, Buffer.from(jwk.e, "base64url")]]));
    }
  }

  get id(): string {
    return base64url(this.credentialId);
  }

  // navigator.credentials.create(), then toJSON().
  create(options: CreationOptions, origin: string, edit: Edits = {}) {
    const clientDataJSON = this.clientData("webauthn.create", options.challenge, origin, edit);
    const credentialId = edit.credentialId ?? this.credentialId;
    const authData = Buffer.concat([
      this.authDataHead(options.rp.id, AT, edit),
      Buffer.alloc(16), // aaguid: zeros, as under attestation "none"
      Buffer.from([credentialId.length >> 8, credentialId.length & 0xff]),
      credentialId,
      edit.publicKey ?? this.cose,
      edit.afterKey ?? Buffer.alloc(0),
    ]);
    const fields = new Map<string, CborValue>([
      ["fmt", edit.fmt ?? "none"],
      ["attStmt", edit.attStmt ?? new Map()],
      ["authData", authData],
    ]);
    const attestationObject = edit.attestationObject ? edit.attestationObject(fields) : encodeCbor(fields);
    return {
      id: edit.id ?? base64url(credentialId),
      rawId: base64url(credentialId),
      type: "public-key",
      clientExtensionResults: {},
      response: { clientDataJSON: base64url(clientDataJSON), attestationObject: base64url(attestationObject), transports: ["internal"] },
    };
  }

  // navigator.credentials.get(), then toJSON().
  get(options: RequestOptions, origin: string, edit: Edits = {}) {
    const clientDataJSON = this.clientData("webauthn.get", options.challenge, origin, edit);
    const authData = this.authDataHead(options.rpId, 0, edit);
    const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
    const key = edit.signWith ?? this.privateKey;
    const signature = this.alg === -8 ? sign(null, signed, key) : sign("sha256", signed, key);
    const sent = edit.authenticatorData ? edit.authenticatorData(authData) : authData;
    return {
      id: edit.id ?? this.id,
      rawId: this.id,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: base64url(clientDataJSON),
        authenticatorData: base64url(sent),
        signature: base64url(signature),
        userHandle: undefined as string | undefined,
      },
    };
  }

  private clientData(type: string, challenge: string, origin: string, edit: Edits): Buffer {
    const c: Record<string, unknown> = { type: edit.type ?? type, challenge: edit.challenge ?? challenge, origin: edit.origin ?? origin };
    if (edit.crossOrigin !== undefined) c.crossOrigin = edit.crossOrigin;
    return Buffer.from(JSON.stringify(c));
  }

  private authDataHead(rpId: string, extra: number, edit: Edits): Buffer {
    const counter = edit.counter ?? (this.counter > 0 ? this.counter++ : 0);
    const count = Buffer.alloc(4);
    count.writeUInt32BE(counter);
    return Buffer.concat([sha256(edit.rpId ?? rpId), Buffer.from([edit.flags ?? (UP | UV | extra)]), count]);
  }
}
