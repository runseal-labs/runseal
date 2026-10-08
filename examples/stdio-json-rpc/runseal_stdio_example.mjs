#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

// Standard-library client: keep the connection open after an admission receipt.
class RunSealClient {
  constructor(binary) {
    this.nextId = 1;
    this.pending = new Map();
    this.executions = new Map();
    this.failure = undefined;
    this.process = spawn(binary, ['service', '--stdio'], { stdio: ['pipe', 'pipe', 'pipe'] });
    this.exited = new Promise((resolveExit) => this.process.once('close', resolveExit));
    this.process.on('error', (error) => this.fail(error));
    this.process.stdin.on('error', (error) => this.fail(error));
    // Drain diagnostics without retaining or publishing potentially sensitive bytes.
    this.process.stderr.resume();
    this.lines = createInterface({ input: this.process.stdout });
    this.lines.on('line', (line) => {
      try { this.receive(JSON.parse(line)); } catch (error) { this.fail(error); }
    });
    this.lines.once('close', () => this.fail(new Error('RunSeal closed the protocol connection')));
  }

  fail(error) {
    this.failure ??= error;
    for (const { reject } of this.pending.values()) reject(error);
    this.pending.clear();
  }

  receive(message) {
    if (message.method === 'event') {
      const event = message.params;
      const state = this.executions.get(event.execution_id) ?? {
        latest: 0,
        bytes: { stdout: 0, stderr: 0, terminal: 0, control: 0 },
        output: { stdout: [], stderr: [], terminal: [], control: [] },
      };
      if (event.event_seq !== state.latest + 1) throw new Error('Unexpected live event sequence');
      if (state.result) throw new Error('Execution event arrived after its terminal event');
      state.latest = event.event_seq;
      for (const stream of ['stdout', 'stderr', 'terminal', 'control']) {
        if (event.type !== `execution.${stream}`) continue;
        if (event.encoding !== 'base64' || !event.data.startsWith('base64:')) throw new Error('Invalid output encoding');
        const bytes = Buffer.from(event.data.slice(7), 'base64');
        if (bytes.length > 65536 || event.bytes !== bytes.length || event.stream_offset !== state.bytes[stream]) throw new Error('Invalid output chunk');
        if (Object.values(state.bytes).reduce((sum, count) => sum + count, 0) + bytes.length > 1024 * 1024) throw new Error('Example output retention limit exceeded');
        state.bytes[stream] += bytes.length;
        state.output[stream].push(bytes);
      }
      if (['execution.finished', 'execution.failed'].includes(event.type)) {
        if (!event.result) throw new Error('Terminal event is missing its result');
        state.result = event.result;
      }
      this.executions.set(event.execution_id, state);
      return;
    }
    const pending = this.pending.get(message.id);
    if (!pending) throw new Error('Unexpected response ID');
    this.pending.delete(message.id);
    if (message.error) pending.reject(new Error(message.error.data?.code ?? message.error.message));
    else pending.resolve(message.result);
  }

  call(method, params = {}) {
    if (this.failure) return Promise.reject(this.failure);
    const id = this.nextId++;
    const response = new Promise((resolveResponse, reject) => this.pending.set(id, { resolve: resolveResponse, reject }));
    this.process.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    return response;
  }

  async waitFor(executionId, predicate) {
    // This example bounds its own wait; it does not impose a service execution timeout.
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      if (this.failure) throw this.failure;
      const state = this.executions.get(executionId);
      if (state && predicate(state)) return state;
      if (state?.result) throw new Error(`Execution ended before expected progress: ${state.result.error?.code ?? `exit ${state.result.exit_code}`}; stdout_bytes=${state.bytes.stdout}; stderr_bytes=${state.bytes.stderr}; terminal_bytes=${state.bytes.terminal}; control_bytes=${state.bytes.control}`);
      await sleep(5);
    }
    throw new Error('Example execution did not make the expected progress');
  }

  async close() {
    this.process.stdin.end();
    const timer = new AbortController();
    let code;
    try { code = await Promise.race([this.exited, sleep(10000, 'timeout', { signal: timer.signal })]); }
    finally { timer.abort(); }
    if (code === 'timeout') { this.process.kill(); throw new Error('RunSeal did not exit after disconnect'); }
    if (code !== 0) throw new Error(`RunSeal exited with code ${code}`);
  }
}

function receivedText(state, stream) {
  return Buffer.concat(state.output[stream]).toString('utf8');
}

function requireProfile(capabilities, args, ioMode, requiredFeatures) {
  const profile = capabilities.execution_profiles?.find((item) =>
    item.sandbox_level === args.policy && item.network_mode === args.network && item.io_mode === ioMode);
  const accepted = args.allowExperimental ? ['supported', 'experimental'] : ['supported'];
  if (!profile || !accepted.includes(profile.status)) {
    throw new Error(`Requested ${ioMode} execution profile is unavailable: ${profile?.status ?? 'missing'}`);
  }
  for (const feature of requiredFeatures) {
    if (!accepted.includes(profile.feature_statuses?.[feature])) {
      throw new Error(`Requested ${ioMode} feature ${feature} is unavailable: ${profile.feature_statuses?.[feature] ?? 'missing'}`);
    }
  }
  return profile;
}

async function runPtyExample(client, args, capabilities) {
  requireProfile(capabilities, args, 'pty', ['pty', 'pty_resize', 'streaming_output', 'stdin_stream']);
  const child = [
    "const { createInterface } = require('node:readline');",
    "if (!process.stdin.isTTY || !process.stdout.isTTY || !process.stderr.isTTY) { process.stderr.write('PTY_NOT_TTY\\n', () => process.exit(8)); }",
    "process.stderr.write('PTY_STDERR\\n');",
    "process.stdout.write(`PTY_READY:${process.stdout.columns}:${process.stdout.rows}\\n`);",
    "const lines = createInterface({ input: process.stdin });",
    "lines.once('line', (line) => process.stdout.write(`PTY_ACK:${line.trim()}\\nPTY_RESIZED:${process.stdout.columns}:${process.stdout.rows}\\n`, () => process.exit(0)));",
  ].join('\n');
  const receipt = await client.call('execute', {
    command: [process.execPath, '-e', child],
    cwd: args.cwd, policy: args.policy, network: { mode: args.network },
    stdin: { mode: 'stream' }, io: { mode: 'pty', rows: 17, cols: 101 },
  });
  if (receipt.status !== 'preparing') throw new Error('PTY execution did not return an admission receipt');
  const id = receipt.execution_id;
  const ready = await client.waitFor(id, (state) => receivedText(state, 'terminal').includes('PTY_READY:101:17'));
  if (!receivedText(ready, 'terminal').includes('PTY_STDERR')) throw new Error('PTY stderr was not merged into terminal output');
  const resized = await client.call('resizeExecution', { execution_id: id, rows: 41, cols: 123 });
  if (resized.accepted !== true) throw new Error('PTY resize was not accepted');
  const input = Buffer.from('hello\r\n');
  await client.call('writeExecutionInput', { execution_id: id, stream: 'stdin', encoding: 'base64', data: `base64:${input.toString('base64')}` });
  const done = await client.waitFor(id, (state) =>
    receivedText(state, 'terminal').includes('PTY_ACK:hello') &&
    receivedText(state, 'terminal').includes('PTY_RESIZED:123:41') && Boolean(state.result));
  if (done.result.status !== 'finished' || done.result.exit_code !== 0 || done.result.cleanup_complete !== true) {
    throw new Error(`PTY execution did not finish cleanly: ${done.result.error?.code ?? done.result.status}`);
  }
  return { execution_id: id, resized: true, terminal_bytes: done.bytes.terminal };
}

async function runControlExample(client, args, capabilities) {
  requireProfile(capabilities, args, 'pipe', ['control_channel', 'execution_cancel', 'streaming_output', 'stdin_stream']);
  const child = [
    "const fs = require('node:fs');",
    "function readExact(fd, size) { const data = Buffer.alloc(size); let offset = 0; while (offset < size) { const count = fs.readSync(fd, data, offset, size - offset, null); if (count === 0) throw new Error('unexpected EOF'); offset += count; } return data; }",
    "function writeAll(fd, data) { let offset = 0; while (offset < data.length) offset += fs.writeSync(fd, data, offset, data.length - offset); }",
    "writeAll(3, Buffer.from('READY')); process.stdout.write('CONTROL_STDOUT\\n'); process.stderr.write('CONTROL_STDERR\\n');",
    "for (let index = 0; index < 3; index += 1) { const input = readExact(0, 1); const request = readExact(3, 4).toString('ascii'); if (input[0] !== 65 + index || request !== `PING${index}`) throw new Error('invalid control round'); writeAll(3, Buffer.from(`PONG${index}`)); }",
    "const probe = Buffer.alloc(1); if (fs.readSync(3, probe, 0, 1, null) !== 0 || fs.readSync(0, probe, 0, 1, null) !== 0) throw new Error('expected half-close');",
  ].join('\n');
  const receipt = await client.call('execute', {
    command: [process.execPath, '-e', child],
    cwd: args.cwd, policy: args.policy, network: { mode: args.network },
    stdin: { mode: 'stream' }, io: { mode: 'pipe', control: { mode: 'pipe', child_fd: 3 } },
  });
  if (receipt.status !== 'preparing') throw new Error('Control execution did not return an admission receipt');
  const id = receipt.execution_id;
  const ready = await client.waitFor(id, (state) => state.bytes.control >= 5);
  if (receivedText(ready, 'control').slice(0, 5) !== 'READY') throw new Error('Control channel did not deliver READY');
  let expectedControlBytes = 5;
  for (let index = 0; index < 3; index += 1) {
    const payload = Buffer.from(`PING${index}`);
    const input = Buffer.from([65 + index]);
    const [inputAck, controlAck] = await Promise.all([
      client.call('writeExecutionInput', { execution_id: id, stream: 'stdin', encoding: 'base64', data: `base64:${input.toString('base64')}` }),
      client.call('writeExecutionInput', { execution_id: id, stream: 'control', encoding: 'base64', data: `base64:${payload.toString('base64')}` }),
    ]);
    if (inputAck.accepted_bytes !== 1 || controlAck.accepted_bytes !== payload.length) throw new Error('Control round was not fully accepted');
    expectedControlBytes += 5;
    const state = await client.waitFor(id, (item) => item.bytes.control >= expectedControlBytes);
    if (receivedText(state, 'control').slice(-5) !== `PONG${index}`) throw new Error(`Control round ${index + 1} did not round-trip`);
  }
  await client.call('closeExecutionInput', { execution_id: id, stream: 'control' });
  await client.call('closeExecutionInput', { execution_id: id, stream: 'stdin' });
  const done = await client.waitFor(id, (state) => Boolean(state.result));
  if (done.result.status !== 'finished' || done.result.exit_code !== 0 || done.result.cleanup_complete !== true) {
    throw new Error(`Control execution did not finish cleanly: ${done.result.error?.code ?? done.result.status}`);
  }
  if (done.bytes.stdout === 0 || done.bytes.stderr === 0) throw new Error('Control execution mixed or lost stdio');
  return { execution_id: id, control_round_trips: 3, control_bytes: done.bytes.control, stdout_bytes: done.bytes.stdout, stderr_bytes: done.bytes.stderr };
}

async function runCancellationExample(client, args, capabilities) {
  requireProfile(capabilities, args, 'pipe', ['execution_cancel', 'streaming_output']);
  const child = "process.stdout.write('CANCEL_READY\\n'); setInterval(() => process.stdout.write('TICK\\n'), 50);";
  const receipt = await client.call('execute', {
    command: [process.execPath, '-e', child],
    cwd: args.cwd, policy: args.policy, network: { mode: args.network },
  });
  if (receipt.status !== 'preparing') throw new Error('Cancellation execution did not return an admission receipt');
  const id = receipt.execution_id;
  await client.waitFor(id, (state) => receivedText(state, 'stdout').includes('CANCEL_READY') && state.bytes.stdout > 0);
  const accepted = await client.call('cancelExecution', { execution_id: id, reason: 'user_requested' });
  if (accepted.status !== 'canceling') throw new Error('Active cancellation was not accepted');
  const done = await client.waitFor(id, (state) => Boolean(state.result));
  if (done.result.status !== 'failed' || done.result.termination_reason !== 'cancelled' || done.result.cleanup_complete !== true) {
    throw new Error(`Cancellation did not cleanly terminate the execution: ${done.result.error?.code ?? done.result.termination_reason}`);
  }
  return { execution_id: id, termination_reason: done.result.termination_reason, cleanup_complete: done.result.cleanup_complete };
}

function options(argv) {
  const result = { runseal: process.env.RUNSEAL_BIN ?? 'runseal', cwd: process.cwd(), policy: 'workspace-write', network: 'disabled', allowExperimental: false };
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (name === '--allow-experimental') { result.allowExperimental = true; continue; }
    if (!['--runseal', '--cwd', '--policy', '--network'].includes(name) || !argv[index + 1]) throw new Error(`Invalid example option: ${name}`);
    result[name.slice(2)] = argv[++index];
  }
  result.cwd = resolve(result.cwd);
  return result;
}

async function main() {
  const args = options(process.argv.slice(2));
  const client = new RunSealClient(args.runseal);
  try {
    const version = await client.call('getVersion');
    if (version.protocol_version !== 'runseal.protocol/v2') throw new Error('This example requires protocol v2');
    const capabilities = await client.call('getCapabilities');
    const accepted = args.allowExperimental ? ['supported', 'experimental'] : ['supported'];
    if (!accepted.includes(capabilities.sandbox_levels?.[args.policy])) throw new Error('Requested sandbox level is unavailable');
    if (args.policy !== 'danger-full-access') {
      if (!accepted.includes(capabilities.network_modes?.[args.network])) throw new Error('Requested network mode is unavailable');
      const setup = await client.call('getSetupStatus', { cwd: args.cwd });
      if (setup.requires_setup) throw new Error('Sandbox setup is not ready');
    }
    requireProfile(capabilities, args, 'pipe', ['streaming_output', 'stdin_stream', 'control_channel', 'execution_cancel']);
    requireProfile(capabilities, args, 'pty', ['pty', 'pty_resize', 'streaming_output', 'stdin_stream']);
    const receipt = await client.call('execute', {
      command: [process.execPath, '-e', "process.stdout.write('READY\\n'); process.stdin.on('data', bytes => process.stdout.write(bytes)); process.stdin.on('end', () => process.exit(0));"],
      cwd: args.cwd, policy: args.policy, network: { mode: args.network }, stdin: { mode: 'stream' },
    });
    if (receipt.status !== 'preparing') throw new Error('Expected admission receipt');
    const id = receipt.execution_id;
    await client.waitFor(id, (state) => state.stdout >= 6);
    // Queries and input continue on the same connection while the child is alive.
    const active = await client.call('getExecution', { execution_id: id });
    if (active.status !== 'running') throw new Error('Expected a running execution');
    let expected = 6;
    for (const bytes of [Buffer.from('round one\n'), Buffer.from([0, 255, 254, 0]), Buffer.from('round three\n')]) {
      await client.call('writeExecutionInput', { execution_id: id, stream: 'stdin', encoding: 'base64', data: `base64:${bytes.toString('base64')}` });
      expected += bytes.length;
      await client.waitFor(id, (state) => state.stdout >= expected);
    }
    await client.call('closeExecutionInput', { execution_id: id, stream: 'stdin' });
    const { result } = await client.waitFor(id, (state) => Boolean(state.result));
    if (result.status !== 'finished' || result.exit_code !== 0) throw new Error('Execution failed');
    const audit = await client.call('getAuditEvents', { execution_id: id });
    if (audit.events.some((event) => 'data' in event)) throw new Error('Audit contains raw output');
    const pty = await runPtyExample(client, args, capabilities);
    const control = await runControlExample(client, args, capabilities);
    const cancellation = await runCancellationExample(client, args, capabilities);
    console.log(JSON.stringify({ command: { execution_id: id, status: result.status, stdout_bytes: result.stdout_bytes }, pty, control, cancellation }));
  } finally { await client.close(); }
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
