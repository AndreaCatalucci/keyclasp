// Synthetic post-lock free-space recovery. Never reads the operator's vault.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../../../../', import.meta.url));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'keyclasp-audit-custody-'));
process.env.KEYCLASP_HOME = root;
const v = await import(path.join(repo, 'dist/vault.js'));
const p = await import(path.join(repo, 'dist/policy.js'));
try {
  v.setMachineIdentityForTests({ stable: Buffer.alloc(32, 41) });
  v.initializeVault('synthetic-passphrase');
  for (let i = 0; i < 500; i++) {
    v.storeSecret('app', 'prod', `API_KEY_${i}`, `synthetic-value-${i}-${'a'.repeat(60)}`);
  }
  const secureDelete = v.getDb().pragma('secure_delete', { simple: true });
  p.mutateAuthorizationRule({ project: 'app', environment: 'prod' }, 'lock',
    (db, rules) => v.transitionRecordCustody(db, rules, p.evaluateAuthorizationRules));
  v.closeDb(); v.clearKey();

  // This fresh process receives no pre-lock snapshot, key, or passphrase.
  const code = `
    import fs from 'node:fs';
    import crypto from 'node:crypto';
    import * as v from ${JSON.stringify(new URL('../../../../dist/vault.js', import.meta.url).href)};
    v.setMachineIdentityForTests({stable:Buffer.alloc(32,41)});
    const raw=fs.readFileSync(process.env.KEYCLASP_HOME+'/vault.db');
    const key=v.getKey(), vaultId=v.getVaultDescriptor().vaultId;
    const current=v.getDb().prepare('SELECT * FROM secrets').all();
    let recovered=0;
    for(const row of current){
      const marker=Buffer.concat([row.record_id,Buffer.from('secretmachine')]);
      let offset=raw.indexOf(marker);
      while(offset>=0){
        const start=offset+marker.length,len=row.encrypted_value.length;
        try{
          const decipher=crypto.createDecipheriv('aes-256-gcm',key,raw.subarray(start+len,start+len+12),{authTagLength:16});
          decipher.setAAD(v.buildRecordAssociatedData({vaultId,recordId:row.record_id,project:row.project,environment:row.environment,name:row.name,keyClass:'machine'}));
          decipher.setAuthTag(raw.subarray(start+len+12,start+len+28));
          const plaintext=Buffer.concat([decipher.update(raw.subarray(start,start+len)),decipher.final()]).toString();
          if(plaintext==='synthetic-value-'+row.name.slice(8)+'-'+'a'.repeat(60)) recovered++;
          break;
        }catch{}
        offset=raw.indexOf(marker,offset+1);
      }
    }
    console.log(JSON.stringify({currentClasses:v.summarizeKeyClasses(),interactiveKeyUnlocked:v.isInteractiveKeyUnlocked(),recoveredWithoutPassphraseOrPreLockSnapshot:recovered}));
    v.closeDb();v.clearKey();
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', code], {
    env: { PATH: process.env.PATH, KEYCLASP_HOME: root }, encoding: 'utf8', timeout: 30000,
  });
  if (child.status !== 0) throw new Error('Synthetic recovery process failed.');
  console.log(JSON.stringify({ secureDelete, ...JSON.parse(child.stdout) }, null, 2));
} finally {
  v.closeDb(); v.clearKey(); v.setMachineIdentityForTests(null);
  fs.rmSync(root, { recursive: true, force: true });
}
