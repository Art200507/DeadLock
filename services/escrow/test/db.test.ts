import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { migrate } from "../src/db.js";
import { harness, timeLockBody, type Harness } from "./helpers.js";

describe("migrations and database guards (PGlite, real Postgres)", () => {
  let h: Harness;
  let vault: string;
  before(async () => {
    h = await harness();
    const body = timeLockBody(h);
    assert.equal((await h.call("POST", "/locks", body)).status, 201);
    vault = body.vaultId;
  });
  after(() => h.close());

  it("applies 001_init once and is idempotent", async () => {
    assert.deepEqual(await migrate(h.db), []);
    const { rows } = await h.db.query<{ name: string }>("select name from schema_migrations");
    assert.deepEqual(rows.map((r) => r.name), ["001_init.sql"]);
  });

  it("audit_log is append-only: no UPDATE, DELETE or TRUNCATE", async () => {
    await assert.rejects(h.db.query("update audit_log set event = 'nothing-happened'"), /append-only/);
    await assert.rejects(h.db.query("delete from audit_log"), /append-only/);
    await assert.rejects(h.db.query("truncate audit_log"), /append-only/);
    const { rows } = await h.db.query("select 1 from audit_log where vault_id = $1", [vault]);
    assert.ok(rows.length > 0, "entries are still there");
  });

  it("sealed lock fields can't be edited", async () => {
    for (const set of [
      `condition_json = '{"type":"time","unlockAt":"2000-01-01T00:00:00.000Z"}'::jsonb`,
      "condition_sha256 = repeat('0', 64)",
      `wrapped_dek = '{"scheme":"mock-kms/v1","keyId":"x","ciphertext":"AA=="}'::jsonb`,
      "unlock_at = now() - interval '1 day'",
      "failsafe_at = now()",
      "vault_id = repeat('a', 32)",
    ]) {
      await assert.rejects(h.db.query(`update locks set ${set} where vault_id = $1`, [vault]), /sealed lock fields cannot change/, set);
    }
  });

  it("status only moves forward, and locks can't be deleted", async () => {
    await h.db.query("update locks set status = 'met' where vault_id = $1", [vault]);
    await assert.rejects(h.db.query("update locks set status = 'sealed' where vault_id = $1", [vault]), /cannot go from met to sealed/);
    await h.db.query("update locks set status = 'released' where vault_id = $1", [vault]);
    for (const back of ["sealed", "met", "failsafe"]) {
      await assert.rejects(
        h.db.query("update locks set status = $2 where vault_id = $1", [vault, back]),
        new RegExp(`cannot go from released to ${back}`),
      );
    }
    await assert.rejects(h.db.query("delete from locks where vault_id = $1", [vault]), /cannot be deleted/);
    await assert.rejects(h.db.query("truncate locks cascade"), /append-only/);
  });

  it("rejects malformed rows at the schema level", async () => {
    await assert.rejects(h.db.query("insert into devices (device_id, public_key) values ('x', 'y')"));
    await assert.rejects(h.db.query("update locks set status = 'open' where vault_id = $1", [vault]));
  });
});
