-- Services registered on the admin page (docs/DESIGN.md §6.2). The services
-- file's are read at start and never stored here.

CREATE TABLE services (
  name                text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$' AND name <> 'auth'),
  roles               text[] NOT NULL,
  mfa_roles           text[] NOT NULL,
  signup              text NOT NULL CHECK (signup IN ('closed', 'invite', 'open')),
  default_role        text,
  manages_own_members boolean NOT NULL DEFAULT false,
  api_key_scopes      text[] NOT NULL DEFAULT '{}',
  app_password_scopes text[] NOT NULL DEFAULT '{}',
  events_url          text,
  -- Held at the last start (§6.2): a copy that starts with it in effect
  -- after that alerts it.
  held                boolean NOT NULL DEFAULT false,
  created_by          text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE clients (
  id                        text PRIMARY KEY,
  service                   text NOT NULL REFERENCES services ON DELETE CASCADE,
  type                      text NOT NULL CHECK (type IN ('confidential', 'public')),
  redirect_uris             text[] NOT NULL,
  post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
  created_at                timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX clients_service ON clients (service);

-- One row, bumped in the transaction of every change to the two tables
-- above: each request reads it and reloads the services when it has moved.
CREATE TABLE services_revision (
  id       boolean PRIMARY KEY DEFAULT true CHECK (id),
  revision bigint NOT NULL DEFAULT 0
);
INSERT INTO services_revision DEFAULT VALUES;
