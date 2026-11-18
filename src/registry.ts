import type { SQL } from "bun";
import { HttpError } from "./http";
import { Services, type Client, type Service, type Signup } from "./services";

// The services in effect (docs/DESIGN.md §6.2): the services file's, read at
// start, and those registered on the admin page, stored here. A copy keeps
// them in memory under the revision it loaded them at, and each request reads
// the revision first, so no copy serves a service another has changed.

export class ServiceRegistry {
  readonly #sql: SQL;
  readonly #file: Service[];
  readonly #log: (line: string) => void;
  #loaded: { revision: bigint; services: Services } | null = null;
  #loading: Promise<{ revision: bigint; services: Services }> | null = null;

  constructor(sql: SQL, file: Services, log: (line: string) => void) {
    this.#sql = sql;
    this.#file = file.all().filter((s) => s.source === "file");
    this.#log = log;
  }

  // The services as of now: one single-row read, and one more query when
  // another request, on any copy, has changed them since.
  async current(): Promise<Services> {
    const [row] = await this.#sql`SELECT revision::text AS revision FROM services_revision`;
    const revision = BigInt(row.revision);
    const loaded = this.#loaded;
    if (loaded && loaded.revision >= revision) return loaded.services;
    // Requests that arrive while a load runs share it, unless it started
    // before the change they saw.
    let loading = this.#loading;
    if (!loading) {
      loading = this.#load().finally(() => {
        if (this.#loading === loading) this.#loading = null;
      });
      this.#loading = loading;
    }
    const fresh = await loading;
    if (fresh.revision < revision) return this.current();
    if (!this.#loaded || this.#loaded.revision < fresh.revision) this.#loaded = fresh;
    return fresh.services;
  }

  // The revision and every registered service in one statement, so they
  // come from one snapshot.
  async #load(): Promise<{ revision: bigint; services: Services }> {
    const rows: DatabaseRow[] = await this.#sql`
      SELECT r.revision::text AS revision, s.name, s.roles, s.mfa_roles, s.signup, s.default_role, s.manages_own_members,
             s.api_key_scopes, s.app_password_scopes, s.events_url,
             c.id AS client_id, c.type AS client_type, c.redirect_uris, c.post_logout_redirect_uris
      FROM services_revision r
      LEFT JOIN services s ON true
      LEFT JOIN clients c ON c.service = s.name
      ORDER BY s.created_at, s.name, c.created_at, c.id`;
    const registered = fromRows(rows);
    const { services, held } = merge(this.#file, registered);
    for (const s of held) {
      if (!this.#file.some((f) => f.name === s.name)) this.#log(`service ${s.name} is held: the services file gives one of its client ids to another service`);
    }
    return { revision: BigInt(rows[0]?.revision ?? "0"), services: new Services(services, held) };
  }
}

interface DatabaseRow {
  revision: string;
  name: string | null;
  roles: string[];
  mfa_roles: string[];
  signup: Signup;
  default_role: string | null;
  manages_own_members: boolean;
  api_key_scopes: string[];
  app_password_scopes: string[];
  events_url: string | null;
  client_id: string | null;
  client_type: "confidential" | "public";
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
}

function fromRows(rows: DatabaseRow[]): Service[] {
  const byName = new Map<string, Service>();
  for (const r of rows) {
    if (r.name === null) continue;
    let s = byName.get(r.name);
    if (!s) {
      s = {
        name: r.name,
        roles: r.roles,
        mfaRoles: r.mfa_roles,
        signup: r.signup,
        defaultRole: r.default_role,
        managesOwnMembers: r.manages_own_members,
        apiKeyScopes: r.api_key_scopes,
        appPasswordScopes: r.app_password_scopes,
        clients: [],
        eventsUrl: r.events_url,
        source: "database",
      };
      byName.set(r.name, s);
    }
    if (r.client_id !== null) {
      s.clients.push({
        id: r.client_id,
        type: r.client_type,
        service: r.name,
        redirectUris: r.redirect_uris,
        postLogoutRedirectUris: r.post_logout_redirect_uris,
      });
    }
  }
  return [...byName.values()];
}

// The file's services win: a registered service is held when the file
// declares its name, or gives one of its client ids to another service.
export function merge(file: Service[], registered: Service[]): { services: Service[]; held: Service[] } {
  const names = new Set(file.map((s) => s.name));
  const clientOwners = new Map(file.flatMap((s) => s.clients.map((c) => [c.id, s.name] as const)));
  const inEffect: Service[] = [];
  const held: Service[] = [];
  for (const s of registered) {
    const clash = names.has(s.name) || s.clients.some((c) => (clientOwners.get(c.id) ?? s.name) !== s.name);
    (clash ? held : inEffect).push(s);
  }
  return { services: [...file, ...inEffect], held };
}

// ------------------------------------------------------------------ writes
//
// Each runs in the caller's transaction, with the change's audit row, and
// starts by bumping the revision: that serializes every change to the
// services, and makes every copy reload them at its next request.

// So every copy can hold every service (§6).
const MAX_REGISTERED = 100;

async function bump(tx: SQL): Promise<void> {
  await tx`UPDATE services_revision SET revision = revision + 1`;
}

// A client id is free for `service` unless another service uses it: a
// registered one, held or not, or one in the file. A held copy of a file
// service keeps each of its clients' types.
async function requireFreeClientId(tx: SQL, current: Services, service: string, c: Client): Promise<void> {
  const [row] = await tx`SELECT service FROM clients WHERE id = ${c.id}`;
  const inEffect = current.client(c.id);
  const fileClient = inEffect && current.get(inEffect.service)?.source === "file" ? inEffect : null;
  const owner = row?.service ?? fileClient?.service ?? null;
  if (owner !== null && owner !== service) throw new HttpError(409, "conflict", `The client id "${c.id}" is used by ${owner}.`);
  if (fileClient && fileClient.type !== c.type) {
    throw new HttpError(400, "invalid_request", `The services file's client ${c.id} is ${fileClient.type}, and a client's type can't change.`);
  }
}

async function insertClient(tx: SQL, service: string, c: Client): Promise<void> {
  await tx`
    INSERT INTO clients (id, service, type, redirect_uris, post_logout_redirect_uris)
    VALUES (${c.id}, ${service}, ${c.type}, ${tx.array(c.redirectUris, "TEXT")}, ${tx.array(c.postLogoutRedirectUris, "TEXT")})`;
}

// Registers a service; held when the file declares its name (§6.2).
export async function insertService(tx: SQL, current: Services, s: Service, actor: string): Promise<{ held: boolean }> {
  await bump(tx);
  const [taken] = await tx`SELECT 1 FROM services WHERE name = ${s.name}`;
  if (taken) throw new HttpError(409, "conflict", `A service named ${s.name} is registered already.`);
  const [count] = await tx`SELECT count(*)::int AS n FROM services`;
  if (count.n >= MAX_REGISTERED) throw new HttpError(409, "conflict", `${MAX_REGISTERED} services are registered, the most there can be; delete one first.`);
  for (const c of s.clients) await requireFreeClientId(tx, current, s.name, c);
  await tx`
    INSERT INTO services (name, roles, mfa_roles, signup, default_role, manages_own_members, api_key_scopes, app_password_scopes, events_url, created_by)
    VALUES (${s.name}, ${tx.array(s.roles, "TEXT")}, ${tx.array(s.mfaRoles, "TEXT")}, ${s.signup}, ${s.defaultRole}, ${s.managesOwnMembers},
            ${tx.array(s.apiKeyScopes, "TEXT")}, ${tx.array(s.appPasswordScopes, "TEXT")}, ${s.eventsUrl}, ${actor})`;
  for (const c of s.clients) await insertClient(tx, s.name, c);
  return { held: current.get(s.name)?.source === "file" };
}

export interface ServiceChange {
  // The fields of §6 that differ, by their JSON names.
  fields: string[];
  addedClients: string[];
  removedClients: string[];
  // Redirect and sign-out URIs that no client of the service had before.
  addedUris: string[];
}

// Replaces a registered service's definition. Its name and its clients' ids
// and types are fixed (§6.2).
export async function replaceService(tx: SQL, current: Services, s: Service): Promise<ServiceChange> {
  await bump(tx);
  const [row] = await tx`
    SELECT name, roles, mfa_roles, signup, default_role, manages_own_members, api_key_scopes, app_password_scopes, events_url
    FROM services WHERE name = ${s.name} FOR UPDATE`;
  if (!row) throw new HttpError(404, "not_found", `There is no registered service "${s.name}".`);
  // Locked, so no token request for one of them is half done (lockClient).
  const oldClients: { id: string; type: string; redirect_uris: string[]; post_logout_redirect_uris: string[] }[] = await tx`
    SELECT id, type, redirect_uris, post_logout_redirect_uris FROM clients WHERE service = ${s.name} ORDER BY created_at, id FOR UPDATE`;
  const before = new Map(oldClients.map((c) => [c.id, c]));

  for (const c of s.clients) {
    const old = before.get(c.id);
    if (!old) await requireFreeClientId(tx, current, s.name, c);
    else if (old.type !== c.type) {
      throw new HttpError(400, "invalid_request", `A client's type can't change: add a ${c.type} client with a new id, and remove ${c.id}.`);
    }
  }

  const removedRoles = (row.roles as string[]).filter((r) => !s.roles.includes(r));
  if (removedRoles.length > 0) await requireUnused(tx, s.name, removedRoles);

  await tx`
    UPDATE services SET roles = ${tx.array(s.roles, "TEXT")}, mfa_roles = ${tx.array(s.mfaRoles, "TEXT")}, signup = ${s.signup},
      default_role = ${s.defaultRole}, manages_own_members = ${s.managesOwnMembers}, api_key_scopes = ${tx.array(s.apiKeyScopes, "TEXT")},
      app_password_scopes = ${tx.array(s.appPasswordScopes, "TEXT")}, events_url = ${s.eventsUrl}, updated_at = now()
    WHERE name = ${s.name}`;
  const kept = new Set(s.clients.map((c) => c.id));
  const removedClients = oldClients.filter((c) => !kept.has(c.id)).map((c) => c.id);
  for (const id of removedClients) {
    await retireClient(tx, id);
    await tx`DELETE FROM clients WHERE id = ${id}`;
  }
  const addedClients: string[] = [];
  for (const c of s.clients) {
    if (before.has(c.id)) {
      await tx`
        UPDATE clients SET redirect_uris = ${tx.array(c.redirectUris, "TEXT")}, post_logout_redirect_uris = ${tx.array(c.postLogoutRedirectUris, "TEXT")}
        WHERE id = ${c.id}`;
    } else {
      await insertClient(tx, s.name, c);
      addedClients.push(c.id);
    }
  }

  const known = new Set(oldClients.flatMap((c) => [...c.redirect_uris, ...c.post_logout_redirect_uris]));
  const addedUris = [...new Set(s.clients.flatMap((c) => [...c.redirectUris, ...c.postLogoutRedirectUris]))].filter((u) => !known.has(u));
  const was: Record<string, unknown> = {
    roles: row.roles,
    mfa_roles: row.mfa_roles,
    signup: row.signup,
    default_role: row.default_role,
    manages_own_members: row.manages_own_members,
    api_key_scopes: row.api_key_scopes,
    app_password_scopes: row.app_password_scopes,
    events_url: row.events_url,
    clients: oldClients.map((c) => [c.id, c.type, c.redirect_uris, c.post_logout_redirect_uris]),
  };
  const is: Record<string, unknown> = {
    roles: s.roles,
    mfa_roles: s.mfaRoles,
    signup: s.signup,
    default_role: s.defaultRole,
    manages_own_members: s.managesOwnMembers,
    api_key_scopes: s.apiKeyScopes,
    app_password_scopes: s.appPasswordScopes,
    events_url: s.eventsUrl,
    clients: s.clients.map((c) => [c.id, c.type, c.redirectUris, c.postLogoutRedirectUris]),
  };
  const fields = Object.keys(is).filter((k) => JSON.stringify(was[k]) !== JSON.stringify(is[k]));
  return { fields, addedClients, removedClients, addedUris };
}

// A role leaves a service only when no one holds it and no pending
// invitation offers it: a row with an undeclared role escapes mfa_roles.
async function requireUnused(tx: SQL, service: string, roles: string[]): Promise<void> {
  const holders: { role: string; n: number }[] = await tx`
    SELECT role, count(*)::int AS n FROM access WHERE service = ${service} AND role IN ${tx(roles)} GROUP BY role ORDER BY role`;
  const invited: { role: string; n: number }[] = await tx`
    SELECT role, count(*)::int AS n FROM invites
    WHERE service = ${service} AND role IN ${tx(roles)} AND accepted_at IS NULL AND expires_at > now()
    GROUP BY role ORDER BY role`;
  const uses = [
    ...holders.map((h) => `${h.n} ${h.n === 1 ? "user holds" : "users hold"} "${h.role}"`),
    ...invited.map((i) => `${i.n} pending ${i.n === 1 ? "invitation offers" : "invitations offer"} "${i.role}"`),
  ];
  if (uses.length > 0) {
    throw new HttpError(409, "conflict", `A role still in use can't be removed: ${uses.join(", ")}. Change their roles or delete the invitations first.`);
  }
}

// Deletes a registered service (§6.2). What is keyed by its name or its
// client ids goes with it, unless the file uses that name or id: then the
// row was a held copy, and those belong to the file's service.
export async function deleteService(tx: SQL, current: Services, name: string): Promise<{ held: boolean }> {
  await bump(tx);
  const [row] = await tx`SELECT name FROM services WHERE name = ${name} FOR UPDATE`;
  if (!row) throw new HttpError(404, "not_found", `There is no registered service "${name}".`);
  const clients: { id: string }[] = await tx`SELECT id FROM clients WHERE service = ${name} ORDER BY id FOR UPDATE`;
  const fileOwns = (id: string) => current.get(current.client(id)?.service ?? "")?.source === "file";
  const nameIsFiles = current.get(name)?.source === "file";
  if (!nameIsFiles) {
    await tx`DELETE FROM access WHERE service = ${name}`;
    await tx`DELETE FROM invites WHERE service = ${name}`;
    await tx`UPDATE credentials SET revoked_at = now() WHERE service = ${name} AND revoked_at IS NULL`;
    await tx`DELETE FROM outbox WHERE service = ${name} AND delivered_at IS NULL AND failed_at IS NULL`;
  }
  for (const c of clients) if (!fileOwns(c.id)) await retireClient(tx, c.id);
  await tx`DELETE FROM services WHERE name = ${name}`;
  return { held: current.get(name)?.source !== "database" };
}

// A client that goes leaves nothing a later client of the same id could use.
async function retireClient(tx: SQL, id: string): Promise<void> {
  await tx`UPDATE client_secrets SET revoked_at = now() WHERE client_id = ${id} AND revoked_at IS NULL`;
  await tx`UPDATE refresh_tokens SET revoked_at = now() WHERE client_id = ${id} AND revoked_at IS NULL`;
  await tx`DELETE FROM auth_codes WHERE client_id = ${id}`;
}

// What a copy can't serve under its configuration, checked at start: a
// registered service with API key scopes needs API_KEY_PREFIX (§6.2).
export async function registeredProblems(sql: SQL, apiKeyPrefix: string | null): Promise<string[]> {
  if (apiKeyPrefix !== null) return [];
  const rows: { name: string }[] = await sql`SELECT name FROM services WHERE api_key_scopes <> '{}' ORDER BY name`;
  return rows.map((r) => `API_KEY_PREFIX is required: the registered service ${r.name} declares api_key_scopes`);
}

// ------------------------------------------------------------------- locks
//
// A request loaded its services when it started; a registered one may have
// changed or gone since. Its row, read again and locked until commit, is what
// a grant, an invitation or a credential is checked against, and a change
// waits for those to commit, or they for it. The file's services can't change
// while the process runs.

export async function lockService(tx: SQL, service: Service): Promise<Service> {
  if (service.source !== "database") return service;
  const [row] = await tx`
    SELECT roles, mfa_roles, signup, default_role, api_key_scopes, app_password_scopes FROM services
    WHERE name = ${service.name} FOR SHARE`;
  if (!row) throw new HttpError(404, "not_found", `There is no service "${service.name}".`);
  return {
    ...service,
    roles: row.roles,
    mfaRoles: row.mfa_roles,
    signup: row.signup,
    defaultRole: row.default_role,
    apiKeyScopes: row.api_key_scopes,
    appPasswordScopes: row.app_password_scopes,
  };
}

// Taken first in a token grant's transaction, before any refresh-token lock,
// so a client's removal can't deadlock with a grant: either the grant
// commits first and the removal revokes what it issued, or the grant finds
// the client gone.
export async function lockClient(tx: SQL, service: Service, client: Client): Promise<void> {
  if (service.source !== "database") return;
  const [row] = await tx`SELECT 1 FROM clients WHERE id = ${client.id} AND service = ${service.name} FOR SHARE`;
  if (!row) throw new HttpError(401, "invalid_client", "Client authentication failed.");
}
