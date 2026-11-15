// Explicit future Node 24.21.0 driver. No action merely from module import.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {registerHooks} from 'node:module';
import {setTimeout as delay} from 'node:timers/promises';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const MAX_BODY = 524288;
const need = (condition, code) => { if (!condition) throw new Error(code); };
const hash = raw => createHash('sha256').update(raw).digest('hex');
const canonical = value => Buffer.from(JSON.stringify(sort(value)), 'utf8');
function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, sort(value[k])]));
  need(value === null || typeof value !== 'number' || Number.isFinite(value), 'NONFINITE_JSON');
  return value;
}
export function exactJSON(raw) {
  const value = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(raw));
  need(canonical(value).equals(raw), 'NONCANONICAL_DISCOVERY_JSON');
  return value;
}
export function requireIDs(actual, expected, version = false) {
  for (const ids of [actual, expected]) {
    need(Array.isArray(ids) && ids.every(x => typeof x === 'string' && x.length > 0 && x.length <= 1024) &&
      new Set(ids).size === ids.length, 'DISCOVERY_IDS');
    need(Boolean(ids.length) !== version, 'VERSION_MEMBERSHIP');
  }
  need(JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort()), 'COMPLETE_UI_INVENTORY_MISMATCH');
}
function pinned(filename, pin, maximum) {
  need(path.isAbsolute(filename) && path.resolve(filename) === filename &&
    fs.realpathSync(filename) === filename && /^[a-f0-9]{64}$/.test(pin), 'SELECTED_FILE_PATH');
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, {bigint:true});
    need(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(maximum), 'SELECTED_FILE_BOUND');
    const raw = fs.readFileSync(fd);
    const after = fs.fstatSync(fd, {bigint:true});
    need(['dev','ino','size','mtimeNs','ctimeNs'].every(k => before[k] === after[k]) &&
      raw.length === Number(before.size) && hash(raw) === pin, 'SELECTED_FILE_PIN');
    return raw;
  } finally { fs.closeSync(fd); }
}
export function originalDeadline(record, now) {
  need(record && typeof record === 'object' && !Array.isArray(record), 'ORIGINAL_CLOCK_FIELDS');
  const fields = record.format === 'forex.original-source-test-clock/1'
    ? ['format','bootstrap_started_utc','test_deadline_utc']
    : ['model_window','model_calls','retry_calls','bootstrap_started_utc','test_deadline_utc'];
  need(Object.keys(record).sort().join('|') === fields.sort().join('|'), 'ORIGINAL_CLOCK_FIELDS');
  for (const key of ['bootstrap_started_utc','test_deadline_utc']) need(typeof record[key] === 'string' && record[key].endsWith('Z'), 'UTC_REQUIRED');
  const start = Date.parse(record.bootstrap_started_utc), end = Date.parse(record.test_deadline_utc);
  need(Number.isFinite(start) && Number.isFinite(end) && start <= now && now < end && end <= start + 7200000, 'ORIGINAL_TEST_WINDOW');
  return end;
}
function args(values) {
  const allowed = new Set(['group','inventory-sha256','original-clock','original-clock-sha256','discovery-fd','release-fd']);
  const result = {};
  need(values.length === allowed.size * 2, 'EXACT_DRIVER_ARGUMENTS');
  for (let i=0; i<values.length; i+=2) {
    const key = values[i].slice(2);
    need(values[i].startsWith('--') && allowed.has(key) && !(key in result), 'DRIVER_ARGUMENT');
    result[key] = values[i+1];
  }
  need(['ui','node-version'].includes(result.group), 'NODE_GROUP');
  for (const key of ['discovery-fd','release-fd']) {
    need(/^[1-9][0-9]*$/.test(result[key]), 'DISCOVERY_FD');
    result[key] = Number(result[key]);
    need(Number.isSafeInteger(result[key]) && result[key] >= 3 && result[key] <= 1024, 'DISCOVERY_FD');
  }
  need(result['discovery-fd'] !== result['release-fd'], 'DISTINCT_DISCOVERY_FDS');
  return result;
}
async function retryIO(action, remaining) {
  for (;;) {
    need(remaining() > 0, 'ORIGINAL_DISCOVERY_DEADLINE');
    try { return action(); }
    catch (error) {
      if (!['EAGAIN','EWOULDBLOCK','EINTR'].includes(error.code)) throw error;
      await delay(Math.min(10, Math.max(1, remaining())));
    }
  }
}
async function exchange(options, ids, remaining) {
  const writer = options['discovery-fd'], reader = options['release-fd'];
  for (const fd of [writer,reader]) need(fs.fstatSync(fd).isFIFO() && /^pipe:\[[0-9]+\]$/.test(fs.readlinkSync('/proc/self/fd/'+fd)), 'ANONYMOUS_PIPE_REQUIRED');
  // Observer must create these inherited endpoints O_NONBLOCK. Native Node has
  // no public fcntl setter; the selected capture is responsible for that flag.
  const raw = canonical({format:'forex.test-driver-discovery/1',group_id:options.group,
    inventory_sha256:options['inventory-sha256'],test_ids:ids});
  need(raw.length > 0 && raw.length <= MAX_BODY, 'DISCOVERY_BODY_BOUND');
  const frame = Buffer.alloc(raw.length + 4); frame.writeUInt32BE(raw.length); raw.copy(frame,4);
  try {
    let offset=0;
    while (offset < frame.length) {
      const count = await retryIO(() => fs.writeSync(writer,frame,offset,Math.min(65536,frame.length-offset)),remaining);
      need(count > 0,'DISCOVERY_WRITE');offset+=count;
    }
  } finally { fs.closeSync(writer); }
  try {
    let received=Buffer.alloc(0), size=null;
    for (;;) {
      const block=Buffer.alloc(Math.min(65536,MAX_BODY+5-received.length));
      const count=await retryIO(() => fs.readSync(reader,block,0,block.length),remaining);
      if (!count) break;
      received=Buffer.concat([received,block.subarray(0,count)]);
      need(received.length <= MAX_BODY+4,'DISCOVERY_READ_BOUND');
      if (size === null && received.length >= 4) {size=received.readUInt32BE();need(size>0 && size<=MAX_BODY,'DISCOVERY_FRAME_BOUND');}
      if (size !== null) need(received.length<=size+4,'EXTRA_DISCOVERY_FRAME');
    }
    need(size!==null && received.length===size+4,'TRUNCATED_DISCOVERY_FRAME');
    const expected = canonical({format:'forex.test-driver-start/1',group_id:options.group,discovery_sha256:hash(raw)});
    exactJSON(received.subarray(4));
    need(received.subarray(4).equals(expected),'DISCOVERY_RELEASE_MISMATCH');
    need(remaining()>0,'ORIGINAL_DISCOVERY_DEADLINE');
  } finally {fs.closeSync(reader);}
}
export async function main(values) {
  const options=args(values);
  need(process.platform==='linux' && process.version==='v24.21.0','SELECTED_NODE_RUNTIME');
  need(!process.env.NODE_OPTIONS && !process.env.NODE_PATH,'UNSELECTED_NODE_OPTIONS');
  need(process.execArgv.length===1 && process.execArgv[0]==='--test-reporter=tap','SELECTED_NODE_REPORTER');
  const clock=exactJSON(pinned(options['original-clock'],options['original-clock-sha256'],16384));
  const end=originalDeadline(clock,Date.now());
  const remaining=() => { originalDeadline(clock,Date.now());return end-Date.now(); };
  const timer=setTimeout(() => {process.stderr.write('ORIGINAL_TEST_DEADLINE\n');process.exit(124);},remaining());
  timer.unref();
  const selection=JSON.parse(pinned(path.join(ROOT,'operational-test-selection.json'),options['inventory-sha256'],4194304));
  const matches=selection.groups.filter(x=>x.group_id===options.group);
  need(matches.length===1,'EXACT_NODE_GROUP');const group=matches[0];
  if (options.group==='node-version') {
    requireIDs([],group.expected_test_ids,true);
    await exchange(options,[],remaining);
    remaining();process.stdout.write(process.version+'\n');clearTimeout(timer);return;
  }
  need(group.mode==='NODE_TAP' && Array.isArray(group.source_files) && group.source_files.length>0,'UI_SOURCE_SELECTION');
  const allowed=new Set(group.source_files.map(name => {
    need(/^tests\/(ui|integration\/node)\/[A-Za-z0-9_.-]+\.test\.mjs$/.test(name),'UI_SOURCE_PATH');
    return pathToFileURL(path.join(ROOT,name)).href;
  }));
  need(allowed.size===group.source_files.length,'DUPLICATE_UI_SOURCE');
  const seen=new Set();const registryURL=new URL('./ui_registration.mjs',import.meta.url).href;
  const hooks=registerHooks({resolve(specifier,context,nextResolve) {
    if (specifier==='node:test') {
      need(allowed.has(context.parentURL),'UNSELECTED_TEST_REGISTRATION');seen.add(context.parentURL);
      return {url:registryURL,shortCircuit:true};
    }
    return nextResolve(specifier,context);
  }});
  try {for (const url of allowed) {remaining();await import(url);}}
  finally {hooks.deregister();}
  need(seen.size===allowed.size,'UI_SOURCE_REGISTRATION_MISSING');
  const {sealRegistration}=await import(registryURL);
  const entries=sealRegistration();const ids=entries.map(x=>x.name);
  requireIDs(ids,group.expected_test_ids);
  await exchange(options,ids,remaining);
  const {default:test}=await import('node:test');
  for (const entry of entries) {
    const timeout=remaining();
    await test(entry.name,{concurrency:false,timeout},entry.fn);
  }
  remaining();clearTimeout(timer);
}

if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  // Do not hold this module's evaluation open while main imports tests which
  // import its pure helpers. That creates a top-level-await dependency cycle.
  void main(process.argv.slice(2)).catch(error => {
    process.stderr.write(String(error.message)+'\n');process.exitCode=1;
  });
}
