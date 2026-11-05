// Build an offline registry from the bun.lock-pinned installed dependency
// closure. No package-manager command, lifecycle script, or network operation
// is executed.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const output=process.argv[2];assert.ok(output);
const root=path.resolve(import.meta.dirname,'../..');
// bun.lock is JSONC (trailing commas). Its packages map is keyed by the
// install path with the node_modules segments dropped ("auth0",
// "auth0-legacy/jose"), and each entry starts with "name@version".
const lock=JSON.parse(fs.readFileSync(path.join(root,'bun.lock'),'utf8').replace(/,(\s*[}\]])/g,'$1'));
const lockedVersion=key=>lock.packages[key]?.[0]?.slice(lock.packages[key][0].lastIndexOf('@')+1);
fs.mkdirSync(output,{recursive:true});
const packages={},seen=new Set();
function visit(dir){
 dir=fs.realpathSync(dir);if(seen.has(dir))return;seen.add(dir);
 const pkg=JSON.parse(fs.readFileSync(path.join(dir,'package.json')));
 const key=path.relative(root,dir).split(path.sep).filter(s=>s!=='node_modules').join('/');
 assert.equal(lockedVersion(key),pkg.version,`${pkg.name} must match lockfile`);
 const file=`${pkg.name.replaceAll('/','-')}-${pkg.version}.tgz`;
 // Preserve the complete published tree, including CommonJS and ESM exports.
 execFileSync('tar',['--exclude=./node_modules','--transform=s,^\\.,package,','-czf',path.join(output,file),'-C',dir,'.']);
 const integrity='sha512-'+createHash('sha512').update(fs.readFileSync(path.join(output,file))).digest('base64');
 (packages[pkg.name]??={})[pkg.version]={...pkg,dist:{tarball:`http://127.0.0.1:9187/${file}`,integrity}};
 const require=createRequire(path.join(dir,'package.json'));
 for(const dep of Object.keys(pkg.dependencies??{})){
  const d=require.resolve.paths(dep).map(base=>path.join(base,dep)).find(d=>fs.existsSync(path.join(d,'package.json')));assert.ok(d,dep);
  visit(d);
 }
}
visit(path.join(root,'node_modules/auth0'));
assert.ok(packages.auth0['7.4.0']);
fs.writeFileSync(path.join(output,'registry.json'),JSON.stringify(packages));
console.log(`offline npm fixture: auth0@7.4.0 and ${seen.size-1} dependency packages pinned to bun.lock`);
