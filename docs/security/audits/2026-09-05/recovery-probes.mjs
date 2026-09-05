// Synthetic audit probes; never uses the operator vault.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL, fileURLToPath} from 'node:url';
const repo=fileURLToPath(new URL('../../../../', import.meta.url));
const v=await import(pathToFileURL(path.join(repo,'dist/vault.js')));
const r=await import(pathToFileURL(path.join(repo,'dist/recovery.js')));
const result={};
const root=fs.mkdtempSync(path.join(os.tmpdir(),'keyclasp-review-recovery-'));
try {
 process.env.KEYCLASP_HOME=path.join(root,'wal-vault');
 v.setMachineIdentityForTests({stable:Buffer.alloc(32,3)});
 v.initializeVault('');v.storeSecret('app','prod','TOKEN','synthetic-backup-value');r.createManagedBackup(path.join(root,'wal-backup'));v.closeDb();v.clearKey();
 const url=pathToFileURL(path.join(repo,'dist/vault.js')).href;
 const child=spawnSync(process.execPath,['--input-type=module','-e',`import * as v from '${url}';v.setMachineIdentityForTests({stable:Buffer.alloc(32,3)});v.storeSecret('app','prod','TOKEN','synthetic-live-value');process.exit(23);`],{env:{PATH:process.env.PATH,KEYCLASP_HOME:process.env.KEYCLASP_HOME},encoding:'utf8',timeout:10000});
 result.writerExitedBeforeClose=child.status===23;
 result.walPresentBeforeRestore=fs.existsSync(path.join(process.env.KEYCLASP_HOME,'vault.db-wal'));
 const restored=r.restoreManagedBackup(path.join(root,'wal-backup'));
 result.restoreReportedSuccess=restored.cleanupWarnings.length===0;
 result.walPresentAfterRestore=fs.existsSync(path.join(process.env.KEYCLASP_HOME,'vault.db-wal'));
 result.restoreReplayedWrongLiveValue=v.resolveSecret('app','prod','TOKEN')==='synthetic-live-value';
 v.closeDb();v.clearKey();
 process.env.KEYCLASP_HOME=path.join(root,'rollback-vault');
 v.initializeVault('');v.storeSecret('app','prod','TOKEN','synthetic-backup-value');r.createManagedBackup(path.join(root,'rollback-backup'));v.storeSecret('app','prod','TOKEN','synthetic-live-value');
 r.setRestoreFaultForTests('crash-after-all-published');
 try {r.restoreManagedBackup(path.join(root,'rollback-backup'));} catch(e){result.initialRestoreInterrupted=e.message.includes('Injected managed-restore crash');}
 r.setRestoreFaultForTests(null);
 const rename=fs.renameSync;
 fs.renameSync=function(a,b){const value=rename(a,b);if(String(a).includes('vault.db.')&&String(a).endsWith('.previous'))throw new Error('synthetic interrupted rollback');return value;};
 try {r.recoverInterruptedManagedRestore();}catch(e){result.rollbackInterrupted=e.message==='synthetic interrupted rollback';}finally{fs.renameSync=rename;}
 try {r.recoverInterruptedManagedRestore();result.secondRecoveryRejected=false;}catch(e){result.secondRecoveryRejected=e.message==='Managed-restore staged file "vault.db" failed journal authentication.';}
 result.rollbackJournalStillPresent=r.hasInterruptedManagedRestore();
 console.log(JSON.stringify(result,null,2));
} finally {v.closeDb();v.clearKey();r.setRestoreFaultForTests(null);fs.rmSync(root,{recursive:true,force:true});}
