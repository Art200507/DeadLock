-- Condition Lock escrow schema, v1.
-- Runs on any Postgres 14+ (Neon, Supabase) and on PGlite for tests.

create table devices (
  device_id   text primary key check (device_id ~ '^[A-Za-z0-9_-]{8,64}$'),
  public_key  text not null unique,          -- Ed25519 raw public key, base64url (32 bytes)
  label       text not null default '',
  created_at  timestamptz not null default now(),
  revoked_at  timestamptz
);

create table locks (
  vault_id          text primary key check (vault_id ~ '^[0-9a-f]{32}$'),
  condition_json    jsonb not null,
  condition_sha256  text not null check (condition_sha256 ~ '^[0-9a-f]{64}$'),
  wrapped_dek       jsonb not null,          -- KeyWrapper output; never the raw key
  status            text not null default 'sealed'
                    check (status in ('sealed', 'met', 'released', 'failsafe')),
  unlock_at         timestamptz,             -- time conditions only
  failsafe_at       timestamptz not null,
  created_by_device text not null references devices (device_id),
  created_at        timestamptz not null default now(),
  met_at            timestamptz,
  released_at       timestamptz
);

create table audit_log (
  id          bigserial primary key,
  vault_id    text,                          -- null for account-level events (device registration)
  event       text not null,
  detail_json jsonb not null default '{}'::jsonb,
  at          timestamptz not null default now()
);
create index audit_log_vault_idx on audit_log (vault_id, id);

-- Replay protection for signed requests.
create table request_nonces (
  device_id  text not null,
  nonce      text not null,
  expires_at timestamptz not null,
  primary key (device_id, nonce)
);

-- audit_log is append-only: no UPDATE, DELETE or TRUNCATE, whoever runs them.
create function condlock_audit_append_only() returns trigger language plpgsql as $$
begin
  raise exception 'audit_log is append-only';
end $$;
create trigger audit_log_no_update_delete before update or delete on audit_log
  for each row execute function condlock_audit_append_only();
create trigger audit_log_no_truncate before truncate on audit_log
  for each statement execute function condlock_audit_append_only();

-- locks: sealed fields never change, status only moves forward, rows are never deleted.
--   sealed -> met -> released      (condition recorded, then key released once)
--   sealed -> released             (verifier released on time evidence)
--   sealed|met -> failsafe         (fail-safe date passed, key released once)
create function condlock_guard_lock() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'locks cannot be deleted';
  end if;
  if new.vault_id <> old.vault_id
     or new.condition_json <> old.condition_json
     or new.condition_sha256 <> old.condition_sha256
     or new.wrapped_dek <> old.wrapped_dek
     or new.unlock_at is distinct from old.unlock_at
     or new.failsafe_at <> old.failsafe_at
     or new.created_by_device <> old.created_by_device
     or new.created_at <> old.created_at then
    raise exception 'sealed lock fields cannot change';
  end if;
  if new.status <> old.status and not (
       (old.status = 'sealed' and new.status in ('met', 'released', 'failsafe'))
    or (old.status = 'met' and new.status in ('released', 'failsafe'))
  ) then
    raise exception 'lock status cannot go from % to %', old.status, new.status;
  end if;
  return new;
end $$;
create trigger locks_guard before update or delete on locks
  for each row execute function condlock_guard_lock();
create trigger locks_no_truncate before truncate on locks
  for each statement execute function condlock_audit_append_only();
