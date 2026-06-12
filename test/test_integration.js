// Integration tests for SSH MCP server tools that use timeouts.
//
// Strategy:
//   1. For *deterministic* cancel tests, we spin up an in-process ssh2 Server
//      bound to an ephemeral port, configured as a "slow" SFTP peer. We give
//      it a known host key and a known user/key, then have the MCP server
//      connect to it. We measure bytes received by the sink to assert that
//      the transfer actually stopped on the server side after the timeout.
//
//   2. For *real-world* smoke tests (connect, exec, simple upload/download),
//      we connect to the live host when env var `LIVE_SSH_HOST` is set.
//      Skipped otherwise.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve as pathResolve } from 'node:path';

import ssh2 from 'ssh2';
const { Server, utils: ssh2utils } = ssh2;
const { parseKey, generateKeyPairSync } = ssh2utils;

// Swallow ECONNRESET/EPIPE etc. that fire on our own fake SSH server's
// TCP sockets when the MCP child is killed mid-test. node:test installs
// its own uncaughtException listener that turns uncaught errors into
// test failures. We use prependListener so our handler runs FIRST;
// for known network-noise errors it silences the error by detaching
// the other listeners for this one call. Real (non-network) errors
// fall through to the test runner unchanged.
const _networkSwallow = function (err) {
  const msg = (err && err.message) || String(err);
  if (msg && /ECONNRESET|ECONNABORTED|EPIPE|ERR_STREAM_DESTROYED/.test(msg)) {
    const all = process.listeners('uncaughtException');
    process.removeAllListeners('uncaughtException');
    for (const l of all) {
      if (l !== _networkSwallow) process.on('uncaughtException', l);
    }
  }
};
process.prependListener('uncaughtException', _networkSwallow);

// ---------------------------------------------------------------------------
// Test harness: spawn the MCP server as a child and speak JSON-RPC to it.
// ---------------------------------------------------------------------------

function startMcpServer(extraEnv = {}) {
  const serverPath = pathResolve('index.js');
  const child = spawn(process.execPath, [serverPath], {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: { ...process.env, ...extraEnv },
  });
  let buffer = '';
  const pending = new Map();
  let nextId = 1;

  child.stdout.on('data', (chunk) => {
    if (process.env.MCP_DEBUG) process.stderr.write(`[stdout] ${chunk.toString().slice(0, 500)}\n`);
    buffer += chunk.toString();
    let nl;
    while ((nl = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch (_) { continue; }
      if (msg.id && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else if (msg.result && msg.result.isError) {
          // MCP tool calls wrap errors as { isError: true, content: [...] }.
          // Surface them as rejections so assert.rejects works as expected.
          const text = msg.result.content && msg.result.content[0] && msg.result.content[0].text || 'tool returned isError';
          const err = new Error(text);
          err.mcpResult = msg.result;
          reject(err);
        } else resolve(msg.result);
      }
    }
  });

  function send(method, params) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }
  const call = (name, args) => send('tools/call', { name, arguments: args });

  return {
    child,
    call,
    async close() {
      // Send SIGTERM and wait briefly for graceful shutdown. If the child
      // doesn't exit (e.g. a lingering SSH socket keeps it alive), escalate
      // to SIGKILL. We swallow ECONNRESET errors that fire as the child's
      // sockets are torn down — they're harmless in a test context.
      const exited = new Promise((r) => child.once('exit', r));
      child.kill('SIGTERM');
      const timeout = new Promise((r) => setTimeout(() => r('timeout'), 500));
      const reason = await Promise.race([exited, timeout]);
      if (reason === 'timeout') {
        child.kill('SIGKILL');
        await Promise.race([
          new Promise((r) => child.once('exit', r)),
          new Promise((r) => setTimeout(r, 500)),
        ]);
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Slow SFTP server: bound to ephemeral port, accepts a single authorized
// key, and stutters on read/write so we can deterministically trigger a
// timeout mid-transfer.
// ---------------------------------------------------------------------------

async function startSlowSftpServer({ bytesPerSecond = 1024 * 1024, streamStall = false, stallExec = false } = {}) {
  // Generate a host key + an authorized key pair on the fly.
  const { private: hostKeyPem } = generateKeyPairSync('ed25519', { length: 256 });
  const { private: clientPrivPem, public: clientPub } = generateKeyPairSync('ed25519', { length: 256 });
  const clientPubParsed = parseKey(clientPub);
  const clientPrivOpenSSH = clientPrivPem; // already OpenSSH format

  // Counters: how many bytes the server actually received/wrote.
  const counters = { bytesReceived: 0, bytesSent: 0, writeEvents: 0, readEvents: 0 };

  // Every command the server received on an `exec` channel, in order. Lets a
  // test assert that the MCP server opened a PARALLEL channel to kill a hung
  // command's process group on timeout (instead of only giving up locally).
  const execCommands = [];

  // In-memory file store shared across SFTP channels, so a file uploaded on
  // one channel (ssh_upload_file) can be read back on another
  // (ssh_download_file). Only used when streamStall is false.
  const fileStore = new Map(); // path -> Buffer

  const server = new Server(
    { hostKeys: [hostKeyPem] },
    (client) => {
      client.on('authentication', (ctx) => {
        if (ctx.method !== 'publickey') return ctx.reject();
        if (!ctx.signature) return ctx.accept();
        // ctx.key is the parsed public key; compare to clientPubParsed.
        if (
          ctx.key.algo === clientPubParsed.type &&
          ctx.key.data.equals(clientPubParsed.getPublicSSH())
        ) {
          ctx.accept();
        } else {
          ctx.reject();
        }
      });
      client.on('ready', () => {
        // Swallow socket-level errors on the per-connection client. When
        // the MCP child is killed mid-test, the underlying TCP socket
        // emits an 'error' event (ECONNRESET). Without a handler that
        // would bubble up as uncaughtException and fail the test.
        client.on('error', () => {});
        client.on('end', () => {});
        // The pattern below is the canonical one from ssh2's own README
        // (see SFTP-only server example). The 'sftp' event is emitted on
        // the per-connection Session, NOT on the Client. The accept()
        // callback returns an SFTP instance in server mode.
        client.on('session', (accept, reject) => {
          const session = accept();
          // Shell support: back the SSH shell channel with a REAL local
          // bash so ssh_execute state tests exercise genuine shell
          // semantics (cd, export, $?) end-to-end through the MCP server.
          session.on('shell', (shellAccept) => {
            const channel = shellAccept();
            const shell = spawn('bash', ['--norc', '--noprofile'], {
              stdio: ['pipe', 'pipe', 'pipe'],
            });
            channel.on('data', (d) => shell.stdin.write(d));
            shell.stdout.on('data', (d) => channel.write(d));
            shell.stderr.on('data', (d) => channel.stderr.write(d));
            shell.on('exit', (code) => {
              try { channel.exit(code === null ? 0 : code); } catch (_) {}
              try { channel.end(); } catch (_) {}
            });
            channel.on('close', () => {
              try { shell.kill('SIGKILL'); } catch (_) {}
            });
            channel.on('error', () => {});
          });
          // Exec channel support. Backs each exec with a real local bash so
          // ssh_execute_script / ssh_upload_and_execute (and the parallel
          // kill channel) run genuinely. Every command is recorded so tests
          // can assert a process-group kill was sent on timeout.
          session.on('exec', (execAccept, execReject, info) => {
            execCommands.push(info.command);
            const channel = execAccept();
            channel.on('error', () => {});
            const isKill = /\bkill\b/.test(info.command);
            // Simulate a hung remote command: accept the channel but never
            // finish, forcing the MCP tool's timeout + cancel path. The kill
            // command itself must still run, so it's exempt.
            if (stallExec && !isKill) {
              return;
            }
            const proc = spawn('bash', ['--norc', '--noprofile', '-c', info.command], {
              stdio: ['ignore', 'pipe', 'pipe'],
            });
            proc.stdout.on('data', (d) => { try { channel.write(d); } catch (_) {} });
            proc.stderr.on('data', (d) => { try { channel.stderr.write(d); } catch (_) {} });
            proc.on('exit', (code) => {
              try { channel.exit(code === null ? 0 : code); } catch (_) {}
              try { channel.end(); } catch (_) {}
            });
            proc.on('error', () => {
              try { channel.exit(127); } catch (_) {}
              try { channel.end(); } catch (_) {}
            });
            channel.on('close', () => { try { proc.kill('SIGKILL'); } catch (_) {} });
          });
          session.on('sftp', (sftpAccept) => {
            const sftp = sftpAccept();
            // READDIR must be registered at the SFTP level (not nested
            // under OPEN), because it uses the directory handle returned
            // by an earlier OPENDIR request.
            sftp.on('READDIR', (reqid, dirHandle) => {
              // Minimal READDIR: emit a single fake entry. Tests only
              // care that the call resolves/times out, not the contents.
              const entry = {
                filename: '.',
                longname: '.',
                attrs: {
                  mode: 0o40755, uid: 0, gid: 0,
                  size: 0, atime: 0, mtime: 0,
                },
              };
              sftp.name(reqid, [entry]);
            }).on('OPENDIR', (reqid, dirPath) => {
              // OPENDIR returns a fake handle; the actual entries come
              // from a subsequent READDIR.
              const dirHandle = Buffer.alloc(4);
              dirHandle.writeUInt32BE(counters.writeEvents + counters.readEvents, 0);
              sftp.handle(reqid, dirHandle);
            });

            // handle id -> { path, isWrite }, per SFTP channel.
            const handles = new Map();
            let nextHandle = 1;

            sftp.on('OPEN', (reqid, filename, flags) => {
              // Pick mode: write = server receives bytes; read = server sends.
              // SSH_FXP_OPEN flags for WRITE are 0x00000002 | 0x00000008 = 0xA
              const isWrite = (flags & 0x00000002) !== 0;
              counters.writeEvents += isWrite ? 1 : 0;
              counters.readEvents += isWrite ? 0 : 1;

              if (isWrite && !streamStall) {
                fileStore.set(filename, Buffer.alloc(0));
              }

              // Fake "handle" = 4 bytes (the ssh2 example uses 4 bytes; we
              // match that for compatibility with the spec).
              const id = nextHandle++;
              handles.set(id, { path: filename, isWrite });
              const handle = Buffer.alloc(4);
              handle.writeUInt32BE(id, 0);
              sftp.handle(reqid, handle);
            }).on('WRITE', (wReqid, wHandle, wOffset, wData) => {
              counters.bytesReceived += wData.length;
              if (streamStall) {
                // Don't ACK. The client will eventually time out at the
                // TCP level (server never acks the SSH_FXP_WRITE).
                return;
              }
              const entry = handles.get(wHandle.readUInt32BE(0));
              if (entry) {
                const existing = fileStore.get(entry.path) || Buffer.alloc(0);
                const needed = wOffset + wData.length;
                const buf = existing.length >= needed
                  ? existing
                  : Buffer.concat([existing, Buffer.alloc(needed - existing.length)]);
                wData.copy(buf, wOffset);
                fileStore.set(entry.path, buf);
              }
              sftp.status(wReqid, 0);
            }).on('READ', (rReqid, rHandle, rOffset, rLen) => {
              if (streamStall) {
                // Don't reply: client will hang.
                return;
              }
              const entry = handles.get(rHandle.readUInt32BE(0));
              const buf = entry ? fileStore.get(entry.path) : undefined;
              if (buf === undefined || rOffset >= buf.length) {
                // STATUS_CODE.EOF = 1
                return sftp.status(rReqid, 1);
              }
              const chunk = buf.slice(rOffset, Math.min(rOffset + rLen, buf.length));
              counters.bytesSent += chunk.length;
              sftp.data(rReqid, chunk);
            }).on('CLOSE', (cReqid, cHandle) => {
              sftp.status(cReqid, 0);
            }).on('MKDIR', (mReqid) => {
              // Pretend the directory already exists (STATUS_CODE.FAILURE =
              // 4) — exactly what a real server answers for mkdir /tmp. The
              // upload handler ignores mkdir errors by design.
              sftp.status(mReqid, 4);
            });
          });
        });
      });
    },
  );

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  // Swallow ECONNRESET/EPIPE etc. that fire on our own fake SSH server's
  // TCP listener when the MCP child is killed mid-test. The default is
  // to re-emit as uncaughtException, which would fail whatever test is
  // running. Registered AFTER the listener is up so we don't miss any.
  server.on('error', () => {});
  const { port } = server.address();

  return {
    host: '127.0.0.1',
    port,
    privateKey: clientPrivOpenSSH,
    username: 'test',
    counters,
    execCommands,
    async close() {
      // Node 26's net.Server.getConnections(cb) returns a count, not an
      // array of sockets, so we can't iterate. Just close the listener
      // and don't wait forever for connections to drain.
      try { server.close(); } catch (_) {}
      await new Promise((resolve) => {
        server.once('close', resolve);
        // Don't wait forever if there are stuck connections.
        setTimeout(() => {
          try { server.close(); } catch (_) {}
          resolve();
        }, 500).unref();
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Test 1: upload with a short timeout against a stalling SFTP server.
// We assert:
//   a) the call rejects with a timeout error mentioning 'ssh_upload_file'
//   b) the server's bytesReceived counter stopped increasing after the
//      timeout (i.e. the transfer actually stopped on the server side)
//   c) the connection was dropped from the MCP server's pool
// ---------------------------------------------------------------------------

test('ssh_upload_file timeout actually stops the transfer on the server', async (t) => {
  const slowServer = await startSlowSftpServer({ streamStall: true });
  t.after(() => slowServer.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  const tmp = mkdtempSync(join(tmpdir(), 'ssh-mcp-test-'));
  const bigFile = join(tmp, 'big.bin');
  // ~5MB so even a fast network needs time.
  writeFileSync(bigFile, Buffer.alloc(5 * 1024 * 1024, 0x41));

  const conn = await mcp.call('ssh_connect', {
    host: slowServer.host,
    port: slowServer.port,
    username: slowServer.username,
    privateKey: slowServer.privateKey,
    connectionId: 'upload-timeout-test',
  });
  assert.equal(conn.content[0].text.startsWith('Successfully connected'), true);

  // Start the upload with a short timeout. Use a 100ms timeout to make the
  // test fast; the stalling server guarantees we'll never finish.
  const t0 = Date.now();
  await assert.rejects(
    mcp.call('ssh_upload_file', {
      localPath: bigFile,
      remotePath: '/tmp/big.bin',
      connectionId: 'upload-timeout-test',
      timeout: 100,
    }),
    (err) => {
      assert.match(err.message, /ssh_upload_file timed out after 100ms/);
      return true;
    },
  );
  const elapsed = Date.now() - t0;
  assert.ok(elapsed >= 100, `expected >=100ms, got ${elapsed}ms`);
  // The cancel grace is 500ms, so we expect <= 700ms total.
  assert.ok(elapsed < 1500, `expected <1500ms (cancel grace), got ${elapsed}ms`);

  // Wait a bit to see if the server keeps receiving bytes.
  const bytesAtTimeout = slowServer.counters.bytesReceived;
  await new Promise((r) => setTimeout(r, 250));
  const bytesAfterWait = slowServer.counters.bytesReceived;
  assert.equal(
    bytesAfterWait,
    bytesAtTimeout,
    `server kept receiving bytes after timeout: ${bytesAtTimeout} -> ${bytesAfterWait}`,
  );

  // The connection should be gone from the pool (we deleted it on timeout).
  const list = await mcp.call('ssh_list_connections', {});
  assert.equal(
    list.content[0].text,
    'No active connections',
    'connection should be removed from pool after timeout',
  );

  rmSync(tmp, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Test 2: download with a short timeout against a stalling server.
// Same assertions, but for the read path.
// ---------------------------------------------------------------------------

test('ssh_download_file timeout actually stops the read on the server', async (t) => {
  const slowServer = await startSlowSftpServer({ streamStall: true });
  t.after(() => slowServer.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  const conn = await mcp.call('ssh_connect', {
    host: slowServer.host,
    port: slowServer.port,
    username: slowServer.username,
    privateKey: slowServer.privateKey,
    connectionId: 'download-timeout-test',
  });
  assert.equal(conn.content[0].text.startsWith('Successfully connected'), true);

  const tmp = mkdtempSync(join(tmpdir(), 'ssh-mcp-test-'));
  const outFile = join(tmp, 'out.bin');

  const t0 = Date.now();
  await assert.rejects(
    mcp.call('ssh_download_file', {
      remotePath: '/tmp/whatever',
      localPath: outFile,
      connectionId: 'download-timeout-test',
      timeout: 100,
    }),
    /ssh_download_file timed out after 100ms/,
  );
  const elapsed = Date.now() - t0;
  assert.ok(elapsed >= 100 && elapsed < 1500, `elapsed=${elapsed}ms`);

  // The local file should NOT have been created (cancel fired before write).
  assert.equal(existsSync(outFile), false, 'local file must not be created on cancel');

  const list = await mcp.call('ssh_list_connections', {});
  assert.equal(list.content[0].text, 'No active connections');

  rmSync(tmp, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Test 3: ssh_list_files timeout drops the connection.
// readdir is callback-based; we cannot easily stall it on the server side
// in this test harness (would need to drop the SFTP channel mid-call).
// We just assert the call rejects with the timeout error and the connection
// is removed from the pool.
// ---------------------------------------------------------------------------

test('ssh_list_files timeout removes connection from pool', async (t) => {
  const slowServer = await startSlowSftpServer({ streamStall: false });
  t.after(() => slowServer.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  await mcp.call('ssh_connect', {
    host: slowServer.host,
    port: slowServer.port,
    username: slowServer.username,
    privateKey: slowServer.privateKey,
    connectionId: 'list-timeout-test',
  });

  // The fake server's readdir handler is not implemented, so even with a
  // large timeout the call will fail. We use a 50ms timeout to force the
  // timeout path to fire *first*.
  await assert.rejects(
    mcp.call('ssh_list_files', {
      remotePath: '/tmp',
      connectionId: 'list-timeout-test',
      timeout: 50,
    }),
    /ssh_list_files timed out after 50ms/,
  );

  const list = await mcp.call('ssh_list_connections', {});
  assert.equal(list.content[0].text, 'No active connections');
});

// ---------------------------------------------------------------------------
// Test 4: invalid timeout values are rejected synchronously.
// ---------------------------------------------------------------------------

test('ssh_upload_file rejects non-finite timeout', async (t) => {
  const slowServer = await startSlowSftpServer({ streamStall: false });
  t.after(() => slowServer.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  // Need an active connection first; otherwise the handler rejects with
  // "No active connection" before it ever sees the timeout argument.
  await mcp.call('ssh_connect', {
    host: slowServer.host,
    port: slowServer.port,
    username: slowServer.username,
    privateKey: slowServer.privateKey,
    connectionId: 'invalid-timeout',
  });

  await assert.rejects(
    mcp.call('ssh_upload_file', {
      localPath: 'whatever',
      remotePath: '/tmp/whatever',
      connectionId: 'invalid-timeout',
      timeout: -1,
    }),
    /Invalid timeout/,
  );
});

// ---------------------------------------------------------------------------
// Test 5: ssh_execute keeps shell state between calls.
// The fake server backs the shell channel with a real local bash, so this
// exercises the full MCP -> ssh2 -> shell session path deterministically.
// ---------------------------------------------------------------------------

const hasLocalBash = (() => {
  try {
    const r = spawnSync('bash', ['--norc', '--noprofile', '-c', 'true'], { timeout: 5000 });
    return r.status === 0;
  } catch (_) {
    return false;
  }
})();

test('ssh_execute keeps state between calls (cd and env persist)', { skip: !hasLocalBash && 'bash not available' }, async (t) => {
  const server = await startSlowSftpServer();
  t.after(() => server.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  await mcp.call('ssh_connect', {
    host: server.host,
    port: server.port,
    username: server.username,
    privateKey: server.privateKey,
    connectionId: 'state-test',
  });

  // cd must persist into the next ssh_execute call.
  const cd = await mcp.call('ssh_execute', {
    command: 'cd /tmp',
    connectionId: 'state-test',
  });
  assert.match(cd.content[0].text, /Exit Code: 0/);

  const pwd = await mcp.call('ssh_execute', {
    command: 'pwd',
    connectionId: 'state-test',
  });
  assert.match(pwd.content[0].text, /^\/tmp$/m, `pwd must report /tmp, got:\n${pwd.content[0].text}`);

  // Environment variables must persist too.
  await mcp.call('ssh_execute', {
    command: 'export MCP_STATE_TEST=state-ok',
    connectionId: 'state-test',
  });
  const echo = await mcp.call('ssh_execute', {
    command: 'echo "$MCP_STATE_TEST"',
    connectionId: 'state-test',
  });
  assert.match(echo.content[0].text, /state-ok/);

  await mcp.call('ssh_disconnect', { connectionId: 'state-test' });
});

test('ssh_execute reports exit code and stderr from the stateful shell', { skip: !hasLocalBash && 'bash not available' }, async (t) => {
  const server = await startSlowSftpServer();
  t.after(() => server.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  await mcp.call('ssh_connect', {
    host: server.host,
    port: server.port,
    username: server.username,
    privateKey: server.privateKey,
    connectionId: 'exit-code-test',
  });

  const fail = await mcp.call('ssh_execute', {
    command: 'echo oops >&2; false',
    connectionId: 'exit-code-test',
  });
  assert.match(fail.content[0].text, /Exit Code: 1/);
  assert.match(fail.content[0].text, /Error Output:\n[\s\S]*oops/);

  // The failed command must not poison the session.
  const ok = await mcp.call('ssh_execute', {
    command: 'echo recovered',
    connectionId: 'exit-code-test',
  });
  assert.match(ok.content[0].text, /Exit Code: 0/);
  assert.match(ok.content[0].text, /recovered/);

  await mcp.call('ssh_disconnect', { connectionId: 'exit-code-test' });
});

// ---------------------------------------------------------------------------
// Timeout must actually CANCEL the remote work, not just give up locally.
// Without a PTY, tearing down the SSH connection does NOT signal a running
// remote command — it keeps executing behind the user's back. The fix opens
// a parallel channel and kills the command's process group. These tests
// assert the kill was actually sent (deterministic); the LIVE test asserts
// the remote process is really gone (real effect).
// ---------------------------------------------------------------------------

async function waitFor(predicate, { timeout = 4000, interval = 50 } = {}) {
  const start = Date.now();
  for (;;) {
    if (predicate()) return true;
    if (Date.now() - start > timeout) return false;
    await new Promise((r) => setTimeout(r, interval));
  }
}

test('ssh_execute timeout kills the remote process group', { skip: !hasLocalBash && 'bash not available' }, async (t) => {
  const server = await startSlowSftpServer();
  t.after(() => server.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  await mcp.call('ssh_connect', {
    host: server.host,
    port: server.port,
    username: server.username,
    privateKey: server.privateKey,
    connectionId: 'kill-exec',
  });

  // A genuinely hung command (sleep blocks the real backing bash).
  await assert.rejects(
    mcp.call('ssh_execute', {
      command: 'sleep 30',
      connectionId: 'kill-exec',
      timeout: 800,
    }),
    /ssh_execute timed out after 800ms/,
  );

  // The server must have received a process-group kill on a parallel channel
  // (kill -TERM/-KILL -- -<pgid>), proving the remote command was cancelled
  // rather than abandoned.
  const sawKill = await waitFor(() =>
    server.execCommands.some((c) => /kill\s+-\w+\s+--\s+-\d+/.test(c)),
  );
  assert.ok(
    sawKill,
    `expected a process-group kill on a parallel channel, got: ${JSON.stringify(server.execCommands)}`,
  );

  // And the dead connection must be dropped from the pool.
  const list = await mcp.call('ssh_list_connections', {});
  assert.equal(list.content[0].text, 'No active connections');
});

test('ssh_execute_script timeout kills the remote script process group', { skip: !hasLocalBash && 'bash not available' }, async (t) => {
  // stallExec makes the script's exec channel hang, forcing the timeout.
  const server = await startSlowSftpServer({ stallExec: true });
  t.after(() => server.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  await mcp.call('ssh_connect', {
    host: server.host,
    port: server.port,
    username: server.username,
    privateKey: server.privateKey,
    connectionId: 'kill-script',
  });

  await assert.rejects(
    mcp.call('ssh_execute_script', {
      script: 'sleep 30',
      connectionId: 'kill-script',
      timeout: 800,
    }),
    /ssh_execute_script timed out after 800ms/,
  );

  // The cancel must target the script's process group, discovered via the
  // unique remote script name (the pattern is bracket-tricked to "[m]cp..."
  // so the kill command doesn't match itself, hence /temp_\d+/ not /mcp_/).
  const sawKill = await waitFor(() =>
    server.execCommands.some((c) => /\bkill\b/.test(c) && /-- -/.test(c) && /temp_\d+/.test(c)),
  );
  assert.ok(
    sawKill,
    `expected a process-group kill targeting the script, got: ${JSON.stringify(server.execCommands)}`,
  );

  const list = await mcp.call('ssh_list_connections', {});
  assert.equal(list.content[0].text, 'No active connections');
});

// ---------------------------------------------------------------------------
// Success paths: a SUCCESSFUL upload/download must resolve, not time out.
// Regression test for the autoDestroy bug: on modern Node, SFTP streams are
// destroyed (stream.destroyed === true) BEFORE 'close'/'end' fires after a
// clean finish, so guards like `if (stream.destroyed) return` swallowed the
// resolve and every successful transfer surfaced as a fake timeout.
// ---------------------------------------------------------------------------

test('ssh_upload_file / ssh_download_file success roundtrip resolves', async (t) => {
  const server = await startSlowSftpServer({ streamStall: false });
  t.after(() => server.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  await mcp.call('ssh_connect', {
    host: server.host,
    port: server.port,
    username: server.username,
    privateKey: server.privateKey,
    connectionId: 'roundtrip',
  });

  const tmp = mkdtempSync(join(tmpdir(), 'ssh-mcp-rt-'));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  const src = join(tmp, 'src.txt');
  const dst = join(tmp, 'dst.txt');
  const content = 'roundtrip-' + Math.random().toString(36).slice(2);
  writeFileSync(src, content);

  // The short timeout is the point: success must resolve well within it
  // instead of being swallowed and surfacing as a timeout.
  const up = await mcp.call('ssh_upload_file', {
    localPath: src,
    remotePath: '/tmp/roundtrip.txt',
    connectionId: 'roundtrip',
    timeout: 5000,
  });
  assert.match(up.content[0].text, /Successfully uploaded/);

  const down = await mcp.call('ssh_download_file', {
    remotePath: '/tmp/roundtrip.txt',
    localPath: dst,
    connectionId: 'roundtrip',
    timeout: 5000,
  });
  assert.match(down.content[0].text, /Successfully downloaded/);
  assert.equal(readFileSync(dst, 'utf8'), content);

  // The connection must still be usable after successful transfers.
  const list = await mcp.call('ssh_list_connections', {});
  assert.match(list.content[0].text, /roundtrip/);

  await mcp.call('ssh_disconnect', { connectionId: 'roundtrip' });
});

test('ssh_execute after `exit` reports a closed shell and recovers', { skip: !hasLocalBash && 'bash not available' }, async (t) => {
  const server = await startSlowSftpServer();
  t.after(() => server.close());

  const mcp = startMcpServer();
  t.after(() => mcp.close());

  await mcp.call('ssh_connect', {
    host: server.host,
    port: server.port,
    username: server.username,
    privateKey: server.privateKey,
    connectionId: 'exit-test',
  });

  // `exit` kills the persistent shell. That must surface as a fast, clear
  // error — not hang until the tool timeout.
  await assert.rejects(
    mcp.call('ssh_execute', {
      command: 'exit',
      connectionId: 'exit-test',
      timeout: 5000,
    }),
    /shell session closed/,
  );

  // The next call must transparently get a fresh shell.
  const echo = await mcp.call('ssh_execute', {
    command: 'echo back-alive',
    connectionId: 'exit-test',
    timeout: 5000,
  });
  assert.match(echo.content[0].text, /back-alive/);

  await mcp.call('ssh_disconnect', { connectionId: 'exit-test' });
});

// ---------------------------------------------------------------------------
// Test 6: LIVE smoke test (skipped unless LIVE_SSH_HOST is set).
// Hits the real SSH server the user provided. Validates that a normal
// connect/exec/upload/download roundtrip works end-to-end against the real
// host.
// ---------------------------------------------------------------------------

const liveHost = process.env.LIVE_SSH_HOST;
const livePort = parseInt(process.env.LIVE_SSH_PORT || '22', 10);
const liveUser = process.env.LIVE_SSH_USER;
const liveKey = process.env.LIVE_SSH_KEY;

test('LIVE: connect, exec, upload, download roundtrip', async (t) => {
  if (!liveHost) {
    t.skip('LIVE_SSH_HOST not set');
    return;
  }
  const mcp = startMcpServer();
  t.after(() => mcp.close());

  const conn = await mcp.call('ssh_connect', {
    host: liveHost,
    port: livePort,
    username: liveUser,
    privateKey: liveKey,
    connectionId: 'live',
    timeout: 5000,
  });
  assert.match(conn.content[0].text, /Successfully connected/);

  const exec = await mcp.call('ssh_execute', {
    command: 'whoami && date',
    connectionId: 'live',
  });
  // Validate the remote user matches LIVE_SSH_USER. Asserting against the
  // env var (not a hard-coded username) keeps the test generic and avoids
  // leaking any specific account name into the repo.
  assert.ok(
    liveUser && exec.content[0].text.includes(liveUser),
    `expected whoami to include LIVE_SSH_USER (${liveUser}), got: ${exec.content[0].text}`,
  );

  // State must persist between ssh_execute calls on the live host too.
  await mcp.call('ssh_execute', { command: 'cd /tmp', connectionId: 'live' });
  const livePwd = await mcp.call('ssh_execute', { command: 'pwd', connectionId: 'live' });
  assert.match(
    livePwd.content[0].text,
    /^\/tmp$/m,
    `cd must persist on the live host, got:\n${livePwd.content[0].text}`,
  );
  await mcp.call('ssh_execute', { command: 'export MCP_LIVE_STATE=live-ok', connectionId: 'live' });
  const liveEcho = await mcp.call('ssh_execute', { command: 'echo "$MCP_LIVE_STATE"', connectionId: 'live' });
  assert.match(liveEcho.content[0].text, /live-ok/);

  // Upload + download a small file.
  const tmp = mkdtempSync(join(tmpdir(), 'ssh-mcp-live-'));
  const src = join(tmp, 'src.txt');
  const dst = join(tmp, 'dst.txt');
  const content = 'live test ' + new Date().toISOString();
  writeFileSync(src, content);

  await mcp.call('ssh_upload_file', {
    localPath: src,
    remotePath: '/tmp/ssh-mcp-live.txt',
    connectionId: 'live',
    timeout: 10000,
  });
  await mcp.call('ssh_download_file', {
    remotePath: '/tmp/ssh-mcp-live.txt',
    localPath: dst,
    connectionId: 'live',
    timeout: 10000,
  });
  assert.equal(readFileSync(dst, 'utf8'), content);

  // Script execution success paths (same autoDestroy guard bug class as
  // upload/download: the script upload's writeStream 'close' was swallowed).
  const script = await mcp.call('ssh_execute_script', {
    script: 'echo from-script\nuname -s',
    connectionId: 'live',
    timeout: 15000,
  });
  assert.match(script.content[0].text, /from-script/);
  assert.match(script.content[0].text, /Exit Code: 0/);

  const uploaded = await mcp.call('ssh_upload_and_execute', {
    script: 'echo from-uploaded-script',
    filename: 'mcp_live_test.sh',
    connectionId: 'live',
    timeout: 15000,
  });
  assert.match(uploaded.content[0].text, /from-uploaded-script/);
  assert.match(uploaded.content[0].text, /Exit Code: 0/);

  await mcp.call('ssh_disconnect', { connectionId: 'live' });
  rmSync(tmp, { recursive: true, force: true });
});

// The real proof: after a tool timeout, the remote command must actually be
// gone from the server's process table — not still running behind the user.
test('LIVE: ssh_execute / ssh_execute_script timeout kills the real remote process', async (t) => {
  if (!liveHost) {
    t.skip('LIVE_SSH_HOST not set');
    return;
  }
  const mcp = startMcpServer();
  t.after(() => mcp.close());

  // Unique markers so we can find (and clean up) exactly our processes.
  const tag1 = 'mcp_kill_exec_' + process.pid + '_1';
  const tag2 = 'mcp_kill_script_' + process.pid + '_2';
  const sleeps = { tag1: 9911, tag2: 9922 };

  const connectArgs = {
    host: liveHost, port: livePort, username: liveUser, privateKey: liveKey, timeout: 5000,
  };

  // --- ssh_execute ---
  await mcp.call('ssh_connect', { ...connectArgs, connectionId: 'killA' });
  await assert.rejects(
    mcp.call('ssh_execute', {
      command: `sleep ${sleeps.tag1} # ${tag1}`,
      connectionId: 'killA',
      timeout: 1500,
    }),
    /ssh_execute timed out/,
  );

  // --- ssh_execute_script ---
  await mcp.call('ssh_connect', { ...connectArgs, connectionId: 'killB' });
  await assert.rejects(
    mcp.call('ssh_execute_script', {
      script: `sleep ${sleeps.tag2} # ${tag2}`,
      connectionId: 'killB',
      timeout: 1500,
    }),
    /ssh_execute_script timed out/,
  );

  // Give the kill channel a moment, then check the remote process table from
  // a FRESH connection. The [s] bracket trick keeps pgrep from matching its
  // own command line.
  await new Promise((r) => setTimeout(r, 1500));
  await mcp.call('ssh_connect', { ...connectArgs, connectionId: 'check' });

  const check1 = await mcp.call('ssh_execute', {
    command: `pgrep -af '[s]leep ${sleeps.tag1}' || echo GONE`,
    connectionId: 'check',
  });
  assert.match(
    check1.content[0].text,
    /GONE/,
    `ssh_execute timeout left the remote process running:\n${check1.content[0].text}`,
  );

  const check2 = await mcp.call('ssh_execute', {
    command: `pgrep -af '[s]leep ${sleeps.tag2}' || echo GONE`,
    connectionId: 'check',
  });
  assert.match(
    check2.content[0].text,
    /GONE/,
    `ssh_execute_script timeout left the remote process running:\n${check2.content[0].text}`,
  );

  // Best-effort cleanup of anything that somehow survived.
  await mcp.call('ssh_execute', {
    command: `pkill -9 -f '[s]leep ${sleeps.tag1}'; pkill -9 -f '[s]leep ${sleeps.tag2}'; true`,
    connectionId: 'check',
  });
  await mcp.call('ssh_disconnect', { connectionId: 'check' });
});
