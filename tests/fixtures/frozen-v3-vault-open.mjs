// Frozen from the pre-v4 vault-open order: key parsing must complete before
// better-sqlite3 receives the database path. Keep this fixture independent of
// current vault code so a future reordering cannot make the regression tautological.
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";

const KEY_FILE_MAGIC = Buffer.from("keyclasp:v3\n", "utf8");
const KEY_FILE_V3_LENGTH = KEY_FILE_MAGIC.length + 1 + 1 + 4 + 32 + 12 + 16 + 32;
const home = process.env.KEYCLASP_HOME;
if (!home) throw new Error("KEYCLASP_HOME is required");

const keyData = fs.readFileSync(path.join(home, ".keyclasp.key"));
if (keyData.length !== KEY_FILE_V3_LENGTH || !keyData.subarray(0, KEY_FILE_MAGIC.length).equals(KEY_FILE_MAGIC)) {
  process.stderr.write("unsupported key format\n");
  process.exit(1);
}

const db = new Database(path.join(home, "vault.db"));
try {
  db.exec("CREATE TABLE frozen_v3_writer_was_here (value TEXT)");
} finally {
  db.close();
}
