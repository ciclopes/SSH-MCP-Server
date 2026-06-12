// Persistent, stateful shell session used by ssh_execute.
//
// Why: conn.exec() opens a brand-new channel (and therefore a brand-new
// shell) per command, so `cd`, `export`, sourced venvs, etc. evaporate
// between calls. A single long-lived shell channel per connection keeps
// that state alive, like a real terminal.
//
// Protocol: each command is sent as one logical shell line
//
//   eval '<command>'; __mcp_rc=$?; printf '\n%s %s\n' '<sentinel>' "$__mcp_rc"; printf '\n%s\n' '<sentinel>' >&2
//
// - eval contains the (single-quote escaped) command, so a syntax error in
//   the command is contained inside eval and cannot consume the sentinel
//   printfs that follow it on the same logical line (fail fast, session
//   survives).
// - The sentinel is unique per command (sequence + random hex), so command
//   output cannot spoof it.
// - The sentinel is printed to BOTH stdout and stderr. Completion requires
//   seeing it on both streams, which guarantees all stderr written before
//   the command finished has been received — no timing-based draining.
//
// Requirements on the remote: a POSIX-compatible login shell (bash, zsh,
// sh, dash...). csh/fish are not supported; commands will fail visibly.

import { randomBytes } from 'crypto';

const CLOSED_MESSAGE =
  'shell session closed (did the command call `exit`?); the next ssh_execute will open a fresh shell';

export class ShellSession {
  // stream: an ssh2 shell channel, or anything exposing
  //   write(data) / on('data') / on('close') / on('error') /
  //   .stderr.on('data') / destroy() / .destroyed
  constructor(stream) {
    this.stream = stream;
    this.closed = false;
    // The remote shell's PID. The shell is its own process-group/session
    // leader, and commands run in the foreground share its group, so on a
    // timeout `kill -- -<pid>` (negative = whole group) reaches the hung
    // command too. Captured during init(); null if capture failed.
    this.pid = null;
    this.seq = 0;
    this.chain = Promise.resolve();
    this.stdoutBuf = '';
    this.stderrBuf = '';
    this.waiter = null;

    stream.on('data', (data) => {
      this.stdoutBuf += data.toString('utf8');
      this._checkSentinel();
    });
    stream.stderr.on('data', (data) => {
      this.stderrBuf += data.toString('utf8');
      this._checkSentinel();
    });
    const onGone = () => {
      this.closed = true;
      const waiter = this.waiter;
      if (waiter) {
        this.waiter = null;
        waiter.reject(new Error(CLOSED_MESSAGE));
      }
    };
    stream.on('close', onGone);
    stream.on('error', onGone);
  }

  // Open a persistent shell on an ssh2 Client connection. `false` disables
  // pty allocation: no prompt noise, no command echo, stderr stays a
  // separate stream.
  static open(conn) {
    return new Promise((resolve, reject) => {
      conn.shell(false, (err, stream) => {
        if (err) {
          return reject(new Error(`Failed to open shell session: ${err.message}`));
        }
        const session = new ShellSession(stream);
        session.init().then(() => resolve(session), reject);
      });
    });
  }

  // Probe the shell once so login banners / profile output are consumed
  // before the first real command, and so an incompatible (non-POSIX)
  // remote shell fails fast instead of corrupting later output. Also
  // captures the shell PID so a timeout can kill the command's process
  // group (see `pid`).
  async init() {
    await this.exec('true');
    const r = await this.exec('echo $$');
    const pid = parseInt(r.stdout.trim(), 10);
    this.pid = Number.isInteger(pid) && pid > 0 ? pid : null;
  }

  // Run a command in the persistent shell. Returns { code, stdout, stderr }.
  // Calls are serialized: a second exec waits for the first to finish.
  exec(command) {
    const run = () => new Promise((resolve, reject) => {
      if (this.closed) {
        return reject(new Error(CLOSED_MESSAGE));
      }
      const sentinel = `__MCP_DONE_${this.seq++}_${randomBytes(4).toString('hex')}__`;
      // Anything that arrived while idle (e.g. background-job output) is
      // not part of this command; drop it so results stay attributable.
      this.stdoutBuf = '';
      this.stderrBuf = '';
      this.waiter = {
        sentinel,
        resolve,
        reject,
        outIdx: -1,
        outEnd: -1,
        errIdx: -1,
        errEnd: -1,
        code: null,
      };
      const escaped = String(command).replace(/'/g, "'\\''");
      this.stream.write(
        `eval '${escaped}\n'; __mcp_rc=$?; ` +
        `printf '\\n%s %s\\n' '${sentinel}' "$__mcp_rc"; ` +
        `printf '\\n%s\\n' '${sentinel}' >&2\n`
      );
    });
    const result = this.chain.then(run, run);
    this.chain = result.then(() => undefined, () => undefined);
    return result;
  }

  _checkSentinel() {
    const waiter = this.waiter;
    if (!waiter) return;

    if (waiter.outIdx === -1) {
      // stdout marker: "\n<sentinel> <exit code>\n". The leading \n comes
      // from our own printf, so slicing at outIdx strips it while keeping
      // the command's own trailing newline (if any) intact.
      const needle = `\n${waiter.sentinel} `;
      const idx = this.stdoutBuf.indexOf(needle);
      if (idx !== -1) {
        const lineEnd = this.stdoutBuf.indexOf('\n', idx + needle.length);
        if (lineEnd !== -1) {
          const parsed = parseInt(this.stdoutBuf.slice(idx + needle.length, lineEnd), 10);
          waiter.outIdx = idx;
          waiter.outEnd = lineEnd + 1;
          waiter.code = Number.isNaN(parsed) ? null : parsed;
        }
      }
    }

    if (waiter.errIdx === -1) {
      const errNeedle = `\n${waiter.sentinel}\n`;
      const idx = this.stderrBuf.indexOf(errNeedle);
      if (idx !== -1) {
        waiter.errIdx = idx;
        waiter.errEnd = idx + errNeedle.length;
      }
    }

    if (waiter.outIdx === -1 || waiter.errIdx === -1) return;

    const stdout = this.stdoutBuf.slice(0, waiter.outIdx);
    const stderr = this.stderrBuf.slice(0, waiter.errIdx);
    this.stdoutBuf = this.stdoutBuf.slice(waiter.outEnd);
    this.stderrBuf = this.stderrBuf.slice(waiter.errEnd);
    this.waiter = null;
    waiter.resolve({ code: waiter.code, stdout, stderr });
  }
}
