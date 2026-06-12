// Unit tests for ShellSession — the persistent, stateful shell used by
// ssh_execute so that working directory, environment variables and other
// shell state survive between calls on the same connection.
//
// ShellSession only needs an ssh2-channel-like stream:
//   write(data) / on('data') / .stderr.on('data') / on('close') /
//   destroy() / .destroyed
// so we can test it against a REAL local bash process without any SSH
// involved. This exercises genuine shell state (cd, export, $?) instead of
// a mock that would just mirror our own protocol back at us.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';

import { ShellSession } from '../lib/shell-session.js';

const hasBash = (() => {
  try {
    const r = spawnSync('bash', ['--norc', '--noprofile', '-c', 'true'], { timeout: 5000 });
    return r.status === 0;
  } catch (_) {
    return false;
  }
})();

// Wrap a local bash child process in the minimal ssh2-channel interface
// ShellSession consumes.
function makeBashStream() {
  const child = spawn('bash', ['--norc', '--noprofile'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const stream = new EventEmitter();
  stream.stderr = new EventEmitter();
  stream.destroyed = false;
  stream.write = (s) => child.stdin.write(s);
  stream.destroy = () => {
    stream.destroyed = true;
    child.kill('SIGKILL');
  };
  child.stdout.on('data', (d) => stream.emit('data', d));
  child.stderr.on('data', (d) => stream.stderr.emit('data', d));
  child.on('exit', () => stream.emit('close'));
  return { stream, child };
}

async function makeSession(t) {
  const { stream, child } = makeBashStream();
  t.after(() => {
    try { child.kill('SIGKILL'); } catch (_) {}
  });
  const session = new ShellSession(stream);
  await session.init();
  return session;
}

test('cd persists between exec calls', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  const cd = await session.exec('cd /tmp');
  assert.equal(cd.code, 0);

  const pwd = await session.exec('pwd');
  assert.equal(pwd.code, 0);
  assert.equal(pwd.stdout.trim(), '/tmp');
});

test('environment variables persist between exec calls', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  await session.exec('export MCP_STATE_TEST=hello-state');
  const echo = await session.exec('echo "$MCP_STATE_TEST"');
  assert.equal(echo.stdout.trim(), 'hello-state');
});

test('exit codes are reported per command', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  assert.equal((await session.exec('true')).code, 0);
  assert.equal((await session.exec('false')).code, 1);
  assert.equal((await session.exec('bash -c "exit 42"')).code, 42);
  // A failure must not poison the next command's exit code.
  assert.equal((await session.exec('true')).code, 0);
});

test('stdout and stderr are captured separately and completely', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  const r = await session.exec('echo to-stdout; echo to-stderr >&2');
  assert.equal(r.stdout.trim(), 'to-stdout');
  assert.equal(r.stderr.trim(), 'to-stderr');
});

test('commands with quotes are passed through intact', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  const r = await session.exec(`echo 'single' "double" \\$dollar`);
  assert.equal(r.stdout.trim(), 'single double $dollar');
});

test('multi-line commands work', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  const r = await session.exec('for i in 1 2 3\ndo\n  echo "line $i"\ndone');
  assert.equal(r.code, 0);
  assert.deepEqual(r.stdout.trim().split('\n'), ['line 1', 'line 2', 'line 3']);
});

test('a syntax error does not break the session', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  const bad = await session.exec('if true; then');
  assert.notEqual(bad.code, 0, 'syntax error must report a non-zero exit code');

  const ok = await session.exec('echo still-alive');
  assert.equal(ok.code, 0);
  assert.equal(ok.stdout.trim(), 'still-alive');
});

test('concurrent exec calls are serialized without output bleed', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  const [a, b, c] = await Promise.all([
    session.exec('echo first'),
    session.exec('echo second'),
    session.exec('echo third'),
  ]);
  assert.equal(a.stdout.trim(), 'first');
  assert.equal(b.stdout.trim(), 'second');
  assert.equal(c.stdout.trim(), 'third');
});

test('output without trailing newline is preserved as-is', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  const r = await session.exec('printf no-newline');
  assert.equal(r.stdout, 'no-newline');
});

test('exit closes the session and the next exec rejects fast', { skip: !hasBash && 'bash not available' }, async (t) => {
  const session = await makeSession(t);

  await assert.rejects(session.exec('exit'), /shell session closed/);
  assert.equal(session.closed, true);
  await assert.rejects(session.exec('echo nope'), /shell session closed/);
});
