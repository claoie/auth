import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Browser, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";

// The icons every page links to, and /favicon.ico, which browsers ask for on
// their own.
describe.skipIf(!TEST_DATABASE_URL)("icons", () => {
  let db: TestDb;
  let t: TestApp;

  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
  });
  afterAll(() => db.drop());

  async function bytes(path: string): Promise<{ res: Response; body: Uint8Array }> {
    const res = await new Browser(t).request(path);
    return { res, body: new Uint8Array(await res.arrayBuffer()) };
  }

  test("/favicon.ico is an icon with 16, 32 and 48 px layers", async () => {
    const { res, body } = await bytes("/favicon.ico");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/x-icon");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=300");
    const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
    // ICONDIR: reserved 0, type 1 (icon), then one 16-byte entry per layer
    // whose first byte is its width.
    expect([view.getUint16(0, true), view.getUint16(2, true)]).toEqual([0, 1]);
    const count = view.getUint16(4, true);
    const widths = Array.from({ length: count }, (_, i) => body[6 + 16 * i]);
    expect(widths.sort((a, b) => a! - b!)).toEqual([16, 32, 48]);
  });

  test("the SVG icon is SVG, with no style or script for a CSP to refuse", async () => {
    const { res, body } = await bytes("/assets/icon.svg");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/svg+xml");
    const text = new TextDecoder().decode(body);
    expect(text.startsWith("<svg ")).toBe(true);
    expect(text).not.toMatch(/<style|<script|\son\w+=|href=/i);
  });

  test("the apple-touch-icon is a 180 px PNG", async () => {
    const { res, body } = await bytes("/assets/apple-touch-icon.png");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
    expect(Array.from(body.slice(0, 8))).toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
    // IHDR's width and height follow the 8-byte signature and the chunk's
    // 8-byte length and type.
    expect([view.getUint32(16), view.getUint32(20)]).toEqual([180, 180]);
  });

  test("every page links the icons", async () => {
    const html = await (await new Browser(t).request("/login")).text();
    expect(html).toContain('<link rel="icon" href="/favicon.ico" sizes="32x32">');
    expect(html).toContain('<link rel="icon" href="/assets/icon.svg" type="image/svg+xml">');
    expect(html).toContain('<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">');
  });

  test("text assets are served unchanged", async () => {
    const res = await new Browser(t).request("/assets/style.css");
    expect(res.headers.get("Content-Type")).toBe("text/css; charset=utf-8");
    expect(await res.text()).toBe(await Bun.file(new URL("./assets/style.css", import.meta.url)).text());
  });

  test("an asset outside the fixed set is a 404", async () => {
    const res = await new Browser(t).request("/assets/favicon.png");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found", error_description: "No such asset." });
  });
});
