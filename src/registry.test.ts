import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { putAccess } from "./access";
import { runCli } from "./cli";
import { base64url, fromBase32, random, sha256 } from "./crypto";
import { deliverDue } from "./events";
import { lockClient } from "./registry";
import { hotp, stepAt } from "./totp";
import { transaction } from "./tx";
import { basic, Browser, makeUser, SERVICES, TEST_DATABASE_URL, testApp, testCopy, testDb, type TestApp, type TestDb } from "./testing/harness";

// Services registered on the admin page (docs/DESIGN.md §6.2) and the
// endpoints that manage them (§7.5): what each change does, on every copy,
// and each refusal sent the input it refuses.
describe.skipIf(!TEST_DATABASE_URL)("registered services", () => {
  let db: TestDb;
  let t: TestApp;
  // A second copy on the same database, as in a rolling deploy.
  let other: TestApp;
  let admin: Browser;
  const PW = "correct horse battery";

  async function adminBrowser(on: TestApp, username: string): Promise<{ b: Browser; id: string }> {
    const id = await makeUser(on, { username, password: PW, access: { auth: "admin" } });
    const b = new Browser(on);
    await b.signIn(username, PW);
    const start = (await (await b.api("POST", "/v1/me/totp", {})).json()) as any;
    await b.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: hotp(fromBase32(start.secret)!, stepAt(Date.now() / 1000)) });
    return { b, id };
  }

  const definition = (name: string, extra: Record<string, unknown> = {}) => ({
    name,
    roles: ["member", "editor"],
    mfa_roles: ["editor"],
    signup: "invite",
    clients: [{ id: name, type: "confidential", redirect_uris: [`https://${name}.example.com/auth/callback`] }],
    ...extra,
  });
  const register = (body: unknown, b = admin) => b.api("POST", "/v1/services", body);
  async function newSecret(clientId: string, b = admin): Promise<string> {
    const res = await b.api("POST", `/v1/clients/${clientId}/secrets`, {});
    expect(res.status).toBe(201);
    return ((await res.json()) as any).secret;
  }
  const errorOf = async (res: Response) => ((await res.json()) as any).error_description as string;

  const verifier = base64url(random(32));
  const authorizeUrl = (clientId: string, redirectUri: string) =>
    `/oauth/authorize?${new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      state: "st",
      code_challenge: base64url(sha256(verifier)),
      code_challenge_method: "S256",
    })}`;
  async function codeFor(b: Browser, clientId: string, redirectUri: string): Promise<string> {
    const res = await b.request(authorizeUrl(clientId, redirectUri));
    const code = new URL(res.headers.get("Location") ?? "https://none.example.com/").searchParams.get("code");
    if (!code) throw new Error(`no code: ${res.status} ${res.headers.get("Location")}`);
    return code;
  }
  const post = (on: TestApp, path: string, fields: Record<string, string>, auth?: string) =>
    new Browser(on).request(path, {
      method: "POST",
      origin: null,
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...(auth ? { Authorization: auth } : {}) },
      body: new URLSearchParams(fields).toString(),
    });
  const exchange = (on: TestApp, clientId: string, secret: string, code: string, redirectUri: string) =>
    post(on, "/oauth/token", { grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier }, basic(clientId, secret));
  // 200 for a client that authenticates, 401 for one that doesn't.
  const introspectAs = (on: TestApp, clientId: string, secret: string) => post(on, "/oauth/introspect", { token: "nothing" }, basic(clientId, secret));

  async function signIn(on: TestApp, username: string, access: Record<string, string> = {}): Promise<{ b: Browser; id: string }> {
    const id = await makeUser(on, { username, password: PW, access });
    const b = new Browser(on);
    await b.signIn(username, PW);
    return { b, id };
  }

  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
    other = testCopy(t);
    ({ b: admin } = await adminBrowser(t, "root"));
    // The other copy has loaded the services before any is registered.
    expect((await new Browser(other).request("/login")).status).toBe(200);
  });
  afterAll(() => db.drop());

  test("a registered service signs people in at once, on another copy too, with the secret the admin page made", async () => {
    const res = await register(definition("journal"));
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({ name: "journal", source: "database", held: false });
    const secret = await newSecret("journal");

    const { b } = await signIn(other, "alice", { journal: "member" });
    const code = await codeFor(b, "journal", "https://journal.example.com/auth/callback");
    const tokens = await exchange(other, "journal", secret, code, "https://journal.example.com/auth/callback");
    expect(tokens.status).toBe(200);
    const claims = JSON.parse(Buffer.from(((await tokens.json()) as any).access_token.split(".")[1], "base64url").toString());
    expect(claims).toMatchObject({ aud: "journal", role: "member", username: "alice" });

    expect(t.alerts.at(-2)).toBe("auth: root registered the service journal, with the redirect URIs https://journal.example.com/auth/callback");
    expect(t.alerts.at(-1)).toBe("auth: root made a new secret for the client journal");
    const [row] = await db.sql`SELECT actor, detail FROM audit WHERE action = 'service.create' ORDER BY id DESC LIMIT 1`;
    expect(row.detail).toEqual({ service: "journal", clients: ["journal"], held: false });
  });

  test("the listing gives each service's source, its confidential clients' live secrets, and the held ones", async () => {
    await register(definition("diary", { clients: [{ id: "diary-ios", type: "public", redirect_uris: ["com.example.diary:/cb"] }] }));
    const body = (await (await admin.api("GET", "/v1/services")).json()) as any;
    const byName = new Map(body.items.map((s: any) => [s.name, s]));
    expect((byName.get("auth") as any).source).toBe("builtin");
    expect((byName.get("wiki") as any).source).toBe("file");
    const journal = byName.get("journal") as any;
    expect(journal.source).toBe("database");
    expect(journal.clients[0].secrets).toHaveLength(1);
    expect(Date.parse(journal.clients[0].secrets[0].created_at)).toBeGreaterThan(Date.now() - 60_000);
    expect((byName.get("diary") as any).clients[0]).toEqual({ id: "diary-ios", type: "public", redirect_uris: ["com.example.diary:/cb"], post_logout_redirect_uris: [] });
    expect(body.held).toEqual([]);
  });

  test("a change on one copy reaches the other's next request: redirect URIs and the pages' form-action", async () => {
    await register(definition("gallery"));
    const { b } = await signIn(other, "bob", { gallery: "member" });
    // The other copy loads gallery as registered.
    await codeFor(b, "gallery", "https://gallery.example.com/auth/callback");

    const moved = { ...definition("gallery"), clients: [{ id: "gallery", type: "confidential", redirect_uris: ["https://photos.example.com/auth/callback"] }] };
    expect((await admin.api("PUT", "/v1/services/gallery", moved)).status).toBe(200);

    const stale = await b.request(authorizeUrl("gallery", "https://gallery.example.com/auth/callback"));
    expect(stale.status).toBe(400);
    expect(await stale.text()).toContain("hasn&#39;t registered");
    await codeFor(b, "gallery", "https://photos.example.com/auth/callback");
    const csp = (await new Browser(other).request("/login")).headers.get("Content-Security-Policy")!;
    expect(csp).toContain(" https://photos.example.com");
    expect(csp).not.toContain("https://gallery.example.com");

    expect(t.alerts.at(-1)).toBe("auth: root changed the clients of the service gallery; added the redirect URIs https://photos.example.com/auth/callback");
    const [row] = await db.sql`SELECT detail FROM audit WHERE action = 'service.update' ORDER BY id DESC LIMIT 1`;
    expect(row.detail).toEqual({ service: "gallery", fields: ["clients"], added_clients: [], removed_clients: [] });
  });

  test("a change applies to sign-in and refresh: a role newly in mfa_roles gets no token from a password-only session", async () => {
    await register(definition("forum"));
    const { b } = await signIn(t, "erin", { forum: "member" });
    const secret = await newSecret("forum");
    const code = await codeFor(b, "forum", "https://forum.example.com/auth/callback");
    const first = (await (await exchange(t, "forum", secret, code, "https://forum.example.com/auth/callback")).json()) as any;
    expect(first.refresh_token).toBeString();

    expect((await admin.api("PUT", "/v1/services/forum", definition("forum", { mfa_roles: ["member", "editor"] }))).status).toBe(200);
    const refreshed = await post(other, "/oauth/token", { grant_type: "refresh_token", refresh_token: first.refresh_token }, basic("forum", secret));
    expect(((await refreshed.json()) as any).error).toBe("invalid_grant");
  });

  test("removing a client revokes its secrets and refresh tokens and drops its codes", async () => {
    await register(definition("wall", { clients: [...definition("wall").clients, { id: "wall-tv", type: "confidential", redirect_uris: ["https://tv.example.com/cb"] }] }));
    const secret = await newSecret("wall-tv");
    const { b, id } = await signIn(t, "frank", { wall: "member" });
    const code = await codeFor(b, "wall-tv", "https://tv.example.com/cb");
    const tokens = (await (await exchange(t, "wall-tv", secret, code, "https://tv.example.com/cb")).json()) as any;
    const unused = await codeFor(b, "wall-tv", "https://tv.example.com/cb");

    const res = await admin.api("PUT", "/v1/services/wall", definition("wall"));
    expect(res.status).toBe(200);
    expect(await introspectAs(t, "wall-tv", secret).then((r) => r.status)).toBe(401);
    const [rt] = await db.sql`SELECT revoked_at FROM refresh_tokens WHERE token_hash = ${sha256(tokens.refresh_token)}`;
    expect(rt.revoked_at).not.toBeNull();
    expect(await db.sql`SELECT 1 FROM auth_codes WHERE code_hash = ${sha256(unused)}`).toHaveLength(0);
    expect(await db.sql`SELECT 1 FROM sessions WHERE user_id = ${id}`).toHaveLength(1);
    const [row] = await db.sql`SELECT detail FROM audit WHERE action = 'service.update' ORDER BY id DESC LIMIT 1`;
    expect(row.detail).toEqual({ service: "wall", fields: ["clients"], added_clients: [], removed_clients: ["wall-tv"] });
  });

  test("a role nobody holds can be removed; one held, or offered by a pending invitation, can't", async () => {
    await register(definition("roster", { roles: ["guest", "member", "editor", "owner"], mfa_roles: ["owner"] }));
    await signIn(t, "gina", { roster: "editor" });
    expect((await admin.api("POST", "/v1/invites", { email: "new@example.com", service: "roster", role: "owner" })).status).toBe(201);

    const without = (...roles: string[]) => definition("roster", { roles: ["guest", "member", "editor", "owner"].filter((r) => !roles.includes(r)), mfa_roles: roles.includes("owner") ? [] : ["owner"] });
    const both = await admin.api("PUT", "/v1/services/roster", without("guest", "editor", "owner"));
    expect(both.status).toBe(409);
    expect(await errorOf(both)).toBe(
      'A role still in use can\'t be removed: 1 user holds "editor", 1 pending invitation offers "owner". Change their roles or delete the invitations first.',
    );
    expect((await admin.api("PUT", "/v1/services/roster", without("guest"))).status).toBe(200);
    const listed = (await (await admin.api("GET", "/v1/services")).json()) as any;
    expect(listed.items.find((s: any) => s.name === "roster").roles).toEqual(["member", "editor", "owner"]);
  });

  test("a grant waits for a role's removal to commit, and the removal for the grant", async () => {
    await register(definition("board"));
    const id = await makeUser(t, { username: "hank", password: PW });
    const board = (await t.app.prepare()).services.get("board")!;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held!: () => void;
    const locked = new Promise<void>((r) => (held = r));
    const grant = transaction(t.app.sql, async (tx, after) => {
      await putAccess(tx, t.app, { userId: id, service: board, role: "editor", actor: "host-cli", ip: null }, after);
      held();
      await gate;
    });
    await locked;
    const csrf = await admin.csrf();
    const removal = admin.api("PUT", "/v1/services/board", definition("board", { roles: ["member"], mfa_roles: [] }), { "X-CSRF-Token": csrf });
    await Bun.sleep(150);
    release();
    await grant;
    const res = await removal;
    expect(res.status).toBe(409);
    expect(await errorOf(res)).toContain('1 user holds "editor"');
  });

  test("a client's removal waits for a token grant in flight, and revokes the refresh token it issued", async () => {
    await register(definition("courier", { clients: [{ id: "courier-ios", type: "public", redirect_uris: ["com.example.courier:/cb"] }] }));
    const id = await makeUser(t, { username: "ivan", password: PW });
    const services = (await t.app.prepare()).services;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held!: () => void;
    const locked = new Promise<void>((r) => (held = r));
    const grant = t.app.sql.begin(async (tx) => {
      await lockClient(tx, services.get("courier")!, services.client("courier-ios")!);
      await tx`
        INSERT INTO refresh_tokens (token_hash, family_id, session_id, user_id, client_id, expires_at)
        VALUES (${sha256("rt_in_flight")}, 'ses_in_flight', NULL, ${id}, 'courier-ios', now() + interval '1 day')`;
      held();
      await gate;
    });
    await locked;
    const csrf = await admin.csrf();
    const removal = admin.api("DELETE", "/v1/services/courier", undefined, { "X-CSRF-Token": csrf });
    await Bun.sleep(150);
    release();
    await grant;
    expect((await removal).status).toBe(204);
    const [rt] = await db.sql`SELECT revoked_at FROM refresh_tokens WHERE token_hash = ${sha256("rt_in_flight")}`;
    expect(rt.revoked_at).not.toBeNull();
  });

  test("a token request for a deleted client is refused", async () => {
    await register(definition("pager"));
    const secret = await newSecret("pager");
    expect((await introspectAs(other, "pager", secret)).status).toBe(200);
    expect((await admin.api("DELETE", "/v1/services/pager")).status).toBe(204);
    expect((await introspectAs(other, "pager", secret)).status).toBe(401);
  });

  test("deleting a service deletes what was granted on it, and one registered again under its name starts empty", async () => {
    const body = definition("ledger", { api_key_scopes: ["ledger:read"], events_url: "http://ledger.internal/auth/events" });
    await register(body);
    const secret = await newSecret("ledger");
    const { b, id } = await signIn(t, "judy", { ledger: "member" });
    const key = await b.api("POST", "/v1/me/api-keys", { name: "script", service: "ledger", scopes: ["ledger:read"] });
    expect(key.status).toBe(201);
    const code = await codeFor(b, "ledger", "https://ledger.example.com/auth/callback");
    const tokens = (await (await exchange(t, "ledger", secret, code, "https://ledger.example.com/auth/callback")).json()) as any;
    expect((await admin.api("POST", "/v1/invites", { email: "later@example.com", service: "ledger", role: "member" })).status).toBe(201);
    expect((await db.sql`SELECT 1 FROM outbox WHERE service = 'ledger' AND delivered_at IS NULL`).length).toBeGreaterThan(0);

    expect((await admin.api("DELETE", "/v1/services/ledger")).status).toBe(204);
    expect(await db.sql`SELECT 1 FROM access WHERE service = 'ledger'`).toHaveLength(0);
    expect(await db.sql`SELECT 1 FROM invites WHERE service = 'ledger'`).toHaveLength(0);
    expect(await db.sql`SELECT 1 FROM outbox WHERE service = 'ledger' AND delivered_at IS NULL AND failed_at IS NULL`).toHaveLength(0);
    expect(await db.sql`SELECT 1 FROM credentials WHERE service = 'ledger' AND revoked_at IS NULL`).toHaveLength(0);
    expect(await db.sql`SELECT 1 FROM client_secrets WHERE client_id = 'ledger' AND revoked_at IS NULL`).toHaveLength(0);
    const [rt] = await db.sql`SELECT revoked_at FROM refresh_tokens WHERE token_hash = ${sha256(tokens.refresh_token)}`;
    expect(rt.revoked_at).not.toBeNull();
    expect(t.alerts.at(-1)).toBe("auth: root deleted the service ledger, with every role, invitation and credential on it");

    expect((await register(body)).status).toBe(201);
    expect((await introspectAs(t, "ledger", secret)).status).toBe(401);
    const access = (await (await admin.api("GET", `/v1/users/${id}/access`)).json()) as any;
    expect(access.items).toEqual([]);
  });

  test("two secrets live at a time, and retiring keeps the newest; a client in the services file gets them the same way", async () => {
    const first = t.secrets.notes!;
    const s1 = await newSecret("notes");
    expect((await introspectAs(t, "notes", first)).status).toBe(200);
    const s2 = await newSecret("notes");
    expect((await introspectAs(t, "notes", first)).status).toBe(401);
    expect((await introspectAs(t, "notes", s1)).status).toBe(200);

    const retired = await admin.api("DELETE", "/v1/clients/notes/old-secrets");
    expect(retired.status).toBe(200);
    expect(await retired.json()).toEqual({ client_id: "notes", retired: 1 });
    expect((await introspectAs(t, "notes", s1)).status).toBe(401);
    expect((await introspectAs(t, "notes", s2)).status).toBe(200);
    const listed = (await (await admin.api("GET", "/v1/services")).json()) as any;
    expect(listed.items.find((s: any) => s.name === "notes").clients[0].secrets).toHaveLength(1);
    t.secrets.notes = s2;
  });

  test("a held copy: the file's service stays in effect, the copy takes over once the file drops it, and nothing granted is lost", async () => {
    const notes = SERVICES.services.find((s) => s.name === "notes")!;
    const res = await register(notes);
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({ name: "notes", source: "database", held: true });
    expect(t.alerts.at(-1)).toBe("auth: root registered the service notes as a held copy of the services file's, with the redirect URIs https://notes.example.com/auth/callback");
    const listed = (await (await admin.api("GET", "/v1/services")).json()) as any;
    expect(listed.items.find((s: any) => s.name === "notes").source).toBe("file");
    expect(listed.held.map((s: any) => [s.name, s.source])).toEqual([["notes", "database"]]);
    const change = await admin.api("PUT", "/v1/services/notes", notes);
    expect(change.status).toBe(409);
    expect(await errorOf(change)).toBe("notes is declared in the services file; change it there.");

    // A copy started with a services file that no longer declares notes.
    const after = testCopy(t, {}, { services: SERVICES.services.filter((s) => s.name !== "notes") });
    const { b } = await signIn(t, "kate", { notes: "reader" });
    const moved = new Browser(after);
    for (const [k, v] of b.cookies) moved.cookies.set(k, v);
    const code = await codeFor(moved, "notes", "https://notes.example.com/auth/callback");
    expect((await exchange(after, "notes", t.secrets.notes!, code, "https://notes.example.com/auth/callback")).status).toBe(200);

    // Deleting the held copy deletes only the copy.
    expect((await admin.api("DELETE", "/v1/services/notes")).status).toBe(204);
    expect(t.alerts.at(-1)).toBe("auth: root deleted the held copy of the service notes");
    expect(await db.sql`SELECT 1 FROM access WHERE service = 'notes'`).toHaveLength(1);
    expect((await introspectAs(t, "notes", t.secrets.notes!)).status).toBe(200);
    expect(((await (await admin.api("GET", "/v1/services")).json()) as any).held).toEqual([]);
  });

  test("a registered service whose client id the file gives another service is held, and logged", async () => {
    await db.sql.begin(async (tx) => {
      await tx`INSERT INTO services (name, roles, mfa_roles, signup, created_by) VALUES ('rogue', '{member}', '{}', 'closed', 'test')`;
      await tx`INSERT INTO clients (id, service, type, redirect_uris) VALUES ('wiki', 'rogue', 'confidential', '{https://rogue.example.com/cb}')`;
      await tx`UPDATE services_revision SET revision = revision + 1`;
    });
    const listed = (await (await admin.api("GET", "/v1/services")).json()) as any;
    expect(listed.items.find((s: any) => s.name === "rogue")).toBeUndefined();
    expect(listed.held.map((s: any) => s.name)).toEqual(["rogue"]);
    expect(t.logs).toContain("service rogue is held: the services file gives one of its client ids to another service");
    const current = await t.app.prepare();
    expect(current.services.client("wiki")!.redirectUris).toEqual(["https://wiki.example.com/auth/callback"]);
    // Deleting it leaves the file's client its secrets.
    expect((await admin.api("DELETE", "/v1/services/rogue")).status).toBe(204);
    expect((await introspectAs(t, "wiki", t.secrets.wiki!)).status).toBe(200);
  });

  test("events go to the service's events_url as it is when they are delivered", async () => {
    await register(definition("radio", { events_url: "http://radio.internal/old" }));
    await signIn(t, "leo", { radio: "member" });
    expect((await admin.api("PUT", "/v1/services/radio", definition("radio", { events_url: "http://radio.internal/new" }))).status).toBe(200);
    const urls: string[] = [];
    const fakeFetch = (async (url: string) => {
      urls.push(url);
      return new Response(null, { status: 202 });
    }) as unknown as typeof fetch;
    while ((await deliverDue(t.app, fakeFetch)) > 0);
    expect(urls).toContain("http://radio.internal/new");
    expect(urls).not.toContain("http://radio.internal/old");
  });

  test("the services are read again only when their revision moves", async () => {
    const a = await t.app.registry.current();
    expect(await t.app.registry.current()).toBe(a);
    await db.sql`UPDATE services_revision SET revision = revision + 1`;
    const b = await t.app.registry.current();
    expect(b).not.toBe(a);
    expect(b.all().map((s) => s.name)).toEqual(a.all().map((s) => s.name));
  });

  test("the break-glass CLI makes a secret for a registered client", async () => {
    await register(definition("kiosk"));
    const out: string[] = [];
    expect(await runCli(["client", "secret", "kiosk"], { app: t.app, mailer: { send: async () => {} }, out: (l) => out.push(l) })).toBe(0);
    expect((await introspectAs(t, "kiosk", out[0]!)).status).toBe(200);
  });

  describe("refusals", () => {
    test("only an auth admin, with a second factor, from the browser", async () => {
      const { b: person } = await signIn(t, "mallory", { wiki: "member" });
      expect((await register(definition("nope"), person)).status).toBe(403);
      expect((await person.api("GET", "/v1/services")).status).toBe(403);
      // An admin whose session used no second factor.
      await makeUser(t, { username: "halfadmin", password: PW, access: { auth: "admin" } });
      const half = new Browser(t);
      await half.signIn("halfadmin", PW);
      expect(await errorOf(await register(definition("nope"), half))).toBe("Admin actions need a sign-in with a second factor.");
      // A service's own client, even one that manages its members.
      const asClient = await new Browser(t).request("/v1/services", {
        method: "POST",
        origin: null,
        headers: { Authorization: basic("wiki", t.secrets.wiki!), "Content-Type": "application/json" },
        body: JSON.stringify(definition("nope")),
      });
      expect(asClient.status).toBe(403);
      expect(await db.sql`SELECT 1 FROM services WHERE name = 'nope'`).toHaveLength(0);
    });

    test("every change needs a sign-in in the last 15 minutes", async () => {
      const { b: stale, id } = await adminBrowser(t, "staleadmin");
      await register(definition("clock"));
      await db.sql`UPDATE sessions SET auth_time = now() - interval '16 minutes' WHERE user_id = ${id}`;
      for (const [method, path, body] of [
        ["POST", "/v1/services", definition("clock2")],
        ["PUT", "/v1/services/clock", definition("clock")],
        ["DELETE", "/v1/services/clock", undefined],
        ["POST", "/v1/clients/clock/secrets", {}],
        ["DELETE", "/v1/clients/clock/old-secrets", undefined],
      ] as const) {
        const res = await stale.api(method, path, body);
        expect([method, path, res.status, ((await res.json()) as any).error]).toEqual([method, path, 403, "reauth_required"]);
      }
      expect((await stale.api("GET", "/v1/services")).status).toBe(200);
    });

    test("a definition that breaks the rules of §6 is refused with every problem listed", async () => {
      const res = await register({ name: "Bad Name", roles: ["member"], mfa_roles: ["admin"], signup: "open", clients: [], extra: 1 });
      expect(res.status).toBe(400);
      expect(await errorOf(res)).toBe(
        'unknown field "extra"; name must match [a-z][a-z0-9-]{0,62}; mfa_roles has "admin", which is not one of roles; default_role must be one of roles when signup is open; clients must be a non-empty array',
      );
      expect(await errorOf(await register(definition("auth")))).toBe('the name "auth" is reserved');
      const insecure = definition("plain", { clients: [{ id: "plain", type: "confidential", redirect_uris: ["http://plain.example.com/cb"] }] });
      expect((await register(insecure)).status).toBe(400);
    });

    test("a taken name or client id is a conflict", async () => {
      await register(definition("atlas"));
      const again = await register(definition("atlas"));
      expect([again.status, await errorOf(again)]).toEqual([409, "A service named atlas is registered already."]);
      const fileClient = await register(definition("atlas2", { clients: [{ id: "tasks-ios", type: "public", redirect_uris: ["com.example.atlas:/cb"] }] }));
      expect([fileClient.status, await errorOf(fileClient)]).toEqual([409, 'The client id "tasks-ios" is used by tasks.']);
      const dbClient = await register(definition("atlas3", { clients: [{ id: "atlas", type: "confidential", redirect_uris: ["https://a.example.com/cb"] }] }));
      expect([dbClient.status, await errorOf(dbClient)]).toEqual([409, 'The client id "atlas" is used by atlas.']);
      const moved = await admin.api("PUT", "/v1/services/atlas", definition("atlas", { clients: [{ id: "wiki", type: "confidential", redirect_uris: ["https://a.example.com/cb"] }] }));
      expect([moved.status, await errorOf(moved)]).toEqual([409, 'The client id "wiki" is used by wiki.']);
    });

    test("API key scopes need API_KEY_PREFIX", async () => {
      const noPrefix = testCopy(t, { API_KEY_PREFIX: "" }, { services: SERVICES.services.filter((s) => !("api_key_scopes" in s)) });
      const b = new Browser(noPrefix);
      for (const [k, v] of admin.cookies) b.cookies.set(k, v);
      const res = await register(definition("vault", { api_key_scopes: ["vault:read"] }), b);
      expect([res.status, await errorOf(res)]).toEqual([400, "api_key_scopes needs API_KEY_PREFIX, which this deployment hasn't set"]);
    });

    test("changes: not to the file's services or auth's, not a name or a client's type, not a service that isn't there", async () => {
      await register(definition("orbit"));
      const cases: [string, string, unknown, number, string][] = [
        ["PUT", "/v1/services/wiki", SERVICES.services[0], 409, "wiki is declared in the services file; change it there."],
        ["DELETE", "/v1/services/wiki", undefined, 409, "wiki is declared in the services file; delete it there."],
        ["PUT", "/v1/services/auth", definition("auth"), 409, "auth's own service can't be changed."],
        ["DELETE", "/v1/services/auth", undefined, 409, "auth's own service can't be deleted."],
        ["PUT", "/v1/services/missing", definition("missing"), 404, 'There is no service "missing".'],
        ["DELETE", "/v1/services/missing", undefined, 404, 'There is no service "missing".'],
        ["PUT", "/v1/services/orbit", definition("orbit2"), 400, "A service's name can't change."],
        [
          "PUT",
          "/v1/services/orbit",
          definition("orbit", { clients: [{ id: "orbit", type: "public", redirect_uris: ["com.example.orbit:/cb"] }] }),
          400,
          "A client's type can't change: add a public client with a new id, and remove orbit.",
        ],
        ["POST", "/v1/clients/tasks-ios/secrets", {}, 409, "A public client has no secret."],
        ["POST", "/v1/clients/missing/secrets", {}, 404, "No such client."],
        ["DELETE", "/v1/clients/missing/old-secrets", undefined, 404, "No such client."],
      ];
      for (const [method, path, body, status, description] of cases) {
        const res = await admin.api(method, path, body);
        expect([method, path, res.status, await errorOf(res)]).toEqual([method, path, status, description]);
      }
    });
  });
});
