// Synthetic audit probes. Does not open the operator's vault or use real credentials.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../../../../', import.meta.url));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'keyclasp-audit-runtime-'));
process.env.KEYCLASP_HOME = path.join(root, 'vault');
const v = await import(path.join(repo, 'dist/vault.js'));
const recovery = await import(path.join(repo, 'dist/recovery.js'));
const run = await import(path.join(repo, 'dist/run.js'));
const observations = {};
try {
  const secret = 'abcd123a';
  let output = '';
  const result = await run.runCommandWithSecrets({
    args: ['--env', 'TOKEN', '--', process.execPath, '-e', 'process.stdout.write(process.env.TOKEN)'],
    baseEnv: {}, secretNames: ['TOKEN'], resolveSecret: () => secret,
    stdout: (chunk) => { output += chunk; }, stderr: () => {},
  });
  observations.outputGuard = { rawSecretEscaped: output === secret, exitCode: result.exitCode };

  v.initializeVault('synthetic-audit-passphrase-only');
  v.storeSecret('audit', 'prod', 'TOKEN', 'synthetic-credential-97531');
  observations.defaultCustody = v.readSecretKeyClass('audit', 'prod', 'TOKEN');
  const backup = path.join(root, 'backup');
  recovery.createManagedBackup(backup);
  v.closeDb(); v.clearKey();
  const env = { PATH: process.env.PATH, KEYCLASP_HOME: process.env.KEYCLASP_HOME };
  const child = spawnSync(process.execPath, [path.join(repo, 'dist/cli.js'), 'run',
    '--project', 'audit', '--environment', 'prod', '--env', 'TOKEN', '--', process.execPath,
    '-e', "process.stdout.write(process.env.TOKEN === 'synthetic-credential-97531' ? 'MATCH' : 'NO')"],
  { env, encoding: 'utf8', timeout: 10000 });
  observations.freshProcessReadWithoutPassphrase = child.status === 0 && child.stdout === 'MATCH';

  fs.writeFileSync(path.join(process.env.KEYCLASP_HOME, '.keyclasp.key'), 'corrupt', { mode: 0o600 });
  const restored = spawnSync(process.execPath, [path.join(repo, 'dist/cli.js'), 'backup', 'restore', backup],
    { env, encoding: 'utf8', timeout: 10000 });
  observations.cliRestoreRejectedCorruptKey = restored.status === 1 && restored.stderr.includes('unsupported format');
  recovery.restoreManagedBackup(backup);
  observations.sameBackupRestoresThroughLibrary = v.resolveSecret('audit', 'prod', 'TOKEN') === 'synthetic-credential-97531';

  v.closeDb(); v.clearKey();
  process.env.KEYCLASP_HOME = path.join(root, 'machine-vault');
  v.initializeVault('');
  let authorized = false;
  try {
    await recovery.createManagedBackupAuthorized(path.join(root, 'machine-backup'), {
      // Model successful operator authorization without invoking the real biometric helper.
      authorize: async () => { authorized = true; },
      ensureUnlocked: async () => {
        // Same first check as the actual CLI's ensureVaultUnlocked().
        if (!v.vaultHasPassphrase()) throw new Error('Interactive custody is not enrolled.');
      },
    });
    observations.machineBackupFailsAfterAuthorization = false;
  } catch (error) {
    observations.machineBackupFailsAfterAuthorization = authorized && error.message === 'Interactive custody is not enrolled.';
  }
  console.log(JSON.stringify(observations, null, 2));
} finally {
  v.closeDb(); v.clearKey();
  fs.rmSync(root, { recursive: true, force: true });
}
