-- Reference schema for the durable control-plane entities (spec section 15).
-- The development control plane currently runs on InMemory stores; this schema
-- documents the constraints a PostgreSQL-backed store must enforce.
CREATE TABLE principal (
  id text PRIMARY KEY,
  public_key bytea NOT NULL,
  fingerprint text NOT NULL UNIQUE,
  state text NOT NULL CHECK (state IN ('active','suspended')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE TABLE auth_challenge (
  id text PRIMARY KEY,
  fingerprint text NOT NULL,
  nonce_hash bytea NOT NULL,
  audience text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE TABLE endpoint (
  id text PRIMARY KEY,
  principal_id text NOT NULL REFERENCES principal(id),
  hostname text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('random','reserved')),
  state text NOT NULL CHECK (state IN ('PENDING','ACTIVE','SUSPENDED','EXPIRED','RELEASED')),
  last_active_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
-- A hostname is unique among non-released endpoints (authoritative allocation guard).
CREATE UNIQUE INDEX endpoint_active_hostname ON endpoint(hostname) WHERE state <> 'RELEASED';
CREATE TABLE plan (
  id text NOT NULL,
  version int NOT NULL,
  price_amount text NOT NULL,
  limits jsonb NOT NULL,
  active_from timestamptz NOT NULL,
  active_until timestamptz,
  PRIMARY KEY (id, version)
);
CREATE TABLE offer (
  id text PRIMARY KEY,
  principal_id text NOT NULL REFERENCES principal(id),
  scope_name text NOT NULL,
  plan_id text NOT NULL,
  terms jsonb NOT NULL, -- immutable snapshot; never rewritten after issue
  expires_at timestamptz NOT NULL,
  state text NOT NULL
);
CREATE TABLE payment (
  id text PRIMARY KEY,
  offer_id text NOT NULL REFERENCES offer(id),
  provider text NOT NULL,
  reference text NOT NULL,
  state text NOT NULL,
  amount text NOT NULL,
  asset text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (provider, reference)
);
CREATE TABLE entitlement (
  id text PRIMARY KEY,
  principal_id text NOT NULL REFERENCES principal(id),
  scope_name text NOT NULL,
  plan_terms jsonb NOT NULL,
  settlement_id text NOT NULL UNIQUE, -- at most one entitlement per settlement
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  state text NOT NULL
);
CREATE TABLE policy_snapshot (
  endpoint_id text NOT NULL,
  version bigint NOT NULL,
  resolved jsonb NOT NULL,
  valid_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (endpoint_id, version)
);
CREATE TABLE usage_period (
  endpoint_id text NOT NULL,
  period_start timestamptz NOT NULL,
  period_end timestamptz NOT NULL,
  used_bytes bigint NOT NULL DEFAULT 0,
  limit_bytes bigint NOT NULL,
  PRIMARY KEY (endpoint_id, period_start)
);
CREATE TABLE usage_batch (
  edge_id text NOT NULL,
  batch_id text NOT NULL,
  endpoint_id text NOT NULL,
  bytes bigint NOT NULL,
  accepted_at timestamptz NOT NULL,
  PRIMARY KEY (edge_id, batch_id, endpoint_id)
);
CREATE TABLE idempotency_key (
  principal_id text NOT NULL,
  operation text NOT NULL,
  key text NOT NULL,
  request_digest bytea NOT NULL,
  response jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (principal_id, operation, key)
);
CREATE TABLE audit_event (
  id text PRIMARY KEY,
  actor text NOT NULL,
  action text NOT NULL,
  target text NOT NULL,
  result text NOT NULL,
  request_id text,
  created_at timestamptz NOT NULL,
  metadata jsonb
);
