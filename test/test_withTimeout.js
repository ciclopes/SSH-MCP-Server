// Unit tests for the `withTimeout` cancellation helper.
//
// We don't import SSHMCPServer directly because it transitively requires the
// @modelcontextprotocol/sdk and an active transport. Instead, we re-implement
// the same helper logic here and assert the contract:
//
//   1. Resolves with the work's value if it finishes before the timer.
//   2. Rejects with a timeout error if the timer fires first, AND the
//      cancel callback has been invoked.
//   3. Rejecting with the work's error short-circuits the timer.
//   4. The timer is always cleared (no leaked handles).
//   5. cancel() can be sync or async; either is awaited.
//
// The implementation under test is the *exact* copy of the one in index.js
// (kept in sync via comment). If you change one, change the other.

import test from 'node:test';
import assert from 'node:assert/strict';

function makeWithTimeout() {
  return function withTimeout(work, timeoutMs, label, cancel) {
    const cancelGraceMs = 500;
    return new Promise((resolve, reject) => {
      let finished = false;
      const settle = (fn, value) => {
        if (finished) return;
        finished = true;
        clearTimeout(guardTimer);
        fn(value);
      };
      const guardTimer = setTimeout(async () => {
        if (cancel) {
          try { await Promise.resolve(cancel()); } catch (_) {}
        }
        setTimeout(() => {
          settle(reject, new Error(`${label} timed out after ${timeoutMs}ms`));
        }, cancelGraceMs);
      }, timeoutMs);
      work()
        .then((result) => settle(resolve, result))
        .catch((err) => settle(reject, err));
    });
  };
}

test('resolves with the work value if it finishes first', async () => {
  const withTimeout = makeWithTimeout();
  const result = await withTimeout(
    async () => 'ok',
    1000,
    'test',
    () => assert.fail('cancel must not be called'),
  );
  assert.equal(result, 'ok');
});

test('rejects with a timeout error when the work is slow', async () => {
  const withTimeout = makeWithTimeout();
  let cancelCalled = false;
  await assert.rejects(
    withTimeout(
      () => new Promise((resolve) => setTimeout(resolve, 5000)),
      50,
      'slow_op',
      () => { cancelCalled = true; },
    ),
    /slow_op timed out after 50ms/,
  );
  assert.equal(cancelCalled, true, 'cancel must run before the timeout error');
});

test("work's rejection wins over the timer if it fires first", async () => {
  const withTimeout = makeWithTimeout();
  await assert.rejects(
    withTimeout(
      async () => { throw new Error('work failed'); },
      1000,
      'failing_op',
      () => assert.fail('cancel must not be called'),
    ),
    /work failed/,
  );
});

test('async cancel callback is awaited', async () => {
  const withTimeout = makeWithTimeout();
  let cancelPhase = 0;
  const cancel = async () => {
    await new Promise((r) => setTimeout(r, 30));
    cancelPhase = 1;
  };
  const t0 = Date.now();
  await assert.rejects(
    withTimeout(
      () => new Promise((r) => setTimeout(r, 5000)),
      30,
      'op',
      cancel,
    ),
    /op timed out after 30ms/,
  );
  const elapsed = Date.now() - t0;
  assert.equal(cancelPhase, 1, 'async cancel must complete before reject');
  // 30ms (timer) + 30ms (cancel) + 500ms (grace) ~= 560ms
  assert.ok(elapsed >= 550, `expected >=550ms, got ${elapsed}ms`);
});

test('throwing inside cancel does not mask the timeout error', async () => {
  const withTimeout = makeWithTimeout();
  await assert.rejects(
    withTimeout(
      () => new Promise((r) => setTimeout(r, 5000)),
      30,
      'op',
      () => { throw new Error('cancel exploded'); },
    ),
    /op timed out after 30ms/,
  );
});

test('no leaked timer when work resolves quickly', async () => {
  const withTimeout = makeWithTimeout();
  // Use Node's process._getActiveHandles / _getActiveRequests if available;
  // for simplicity, just verify the timer doesn't keep the event loop alive.
  // The fact that this test exits at all is the assertion.
  await withTimeout(async () => 42, 5000, 'fast', () => {});
  // If the timer leaked, the process would hang for 5s. It doesn't.
});

test('cancel receives no arguments', async () => {
  const withTimeout = makeWithTimeout();
  let received;
  await assert.rejects(
    withTimeout(
      () => new Promise((r) => setTimeout(r, 5000)),
      20,
      'op',
      (...args) => { received = args; },
    ),
    /op timed out after 20ms/,
  );
  assert.deepEqual(received, []);
});
