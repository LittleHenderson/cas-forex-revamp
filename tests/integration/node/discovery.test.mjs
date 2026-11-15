// Authored integration-owned future tests. NOT_RUN.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createRegistry} from '../../../ui_registration.mjs';
import {exactJSON, requireIDs, originalDeadline} from '../../../operational_node_group.mjs';

test('OC01 registration retains exact callbacks without entering test bodies', () => {
  const registry=createRegistry();let entered=0;const callback=()=>{entered++;};
  registry.register('one',callback);const entries=registry.seal();
  assert.equal(entered,0);assert.equal(entries[0].fn,callback);
  assert(Object.isFrozen(entries));assert(Object.isFrozen(entries[0]));
});
test('OC01 late or duplicate registration cannot change observed membership', () => {
  const registry=createRegistry();registry.register('one',()=>{});
  assert.throws(()=>registry.register('one',()=>{}));registry.seal();
  assert.throws(()=>registry.register('two',()=>{}));assert.throws(()=>registry.seal());
});
test('OC01 unsupported skip options or callback signatures fail closed', () => {
  for (const args of [['one',{skip:true},()=>{}],['one',null],['one',(t,done)=>done()]]) {
    assert.throws(()=>createRegistry().register(...args));
  }
});
test('OC01 a passed subset cannot supply complete UI discovery', () => {
  assert.throws(()=>requireIDs(['one'],['one','two']));
  assert.throws(()=>requireIDs(['one','one'],['one']));
  requireIDs(['two','one'],['one','two']);
});
test('OC01 version group alone permits an empty collected inventory', () => {
  requireIDs([],[],true);assert.throws(()=>requireIDs([],[]));
  assert.throws(()=>requireIDs(['one'],['one'],true));
});
test('OC01 duplicate JSON keys cannot substitute a discovery release binding', () => {
  assert.throws(()=>exactJSON(Buffer.from('{"a":1,"a":2}')));
  assert.throws(()=>exactJSON(Buffer.from('{"b":1,"a":2}')));
  assert.deepEqual(exactJSON(Buffer.from('{"a":2,"b":1}')),{a:2,b:1});
});
test('OC01 original deadline cannot restart at driver invocation', () => {
  const clock={model_window:{},model_calls:32,retry_calls:0,
    bootstrap_started_utc:'2030-01-01T00:00:00Z',test_deadline_utc:'2030-01-01T02:00:00Z'};
  assert.equal(originalDeadline(clock,Date.parse('2030-01-01T01:00:00Z')),Date.parse(clock.test_deadline_utc));
  assert.throws(()=>originalDeadline(clock,Date.parse(clock.test_deadline_utc)));
  clock.test_deadline_utc='2030-01-01T02:00:01Z';
  assert.throws(()=>originalDeadline(clock,Date.parse('2030-01-01T01:00:00Z')));
});

test('SOURCECLOCK source-only record needs no model window or model authority', () => {
  const clock={format:'forex.original-source-test-clock/1',
    bootstrap_started_utc:'2030-01-01T00:00:00Z',test_deadline_utc:'2030-01-01T02:00:00Z'};
  assert.equal(originalDeadline(clock,Date.parse('2030-01-01T01:00:00Z')),Date.parse(clock.test_deadline_utc));
});
test('SOURCECLOCK extra model fields cannot extend source-only permission', () => {
  const clock={format:'forex.original-source-test-clock/1',model_calls:32,
    bootstrap_started_utc:'2030-01-01T00:00:00Z',test_deadline_utc:'2030-01-01T02:00:00Z'};
  assert.throws(()=>originalDeadline(clock,Date.parse('2030-01-01T01:00:00Z')));
});
test('SOURCECLOCK new format cannot reset the original deadline', () => {
  const clock={format:'forex.original-source-test-clock/1',
    bootstrap_started_utc:'2030-01-01T00:00:00Z',test_deadline_utc:'2030-01-01T02:00:00Z'};
  assert.throws(()=>originalDeadline(clock,Date.parse(clock.test_deadline_utc)));
  clock.test_deadline_utc='2030-01-01T02:00:01Z';
  assert.throws(()=>originalDeadline(clock,Date.parse('2030-01-01T01:00:00Z')));
});
