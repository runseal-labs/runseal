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
      const state = this.executions.get(event.execution_id) ?? { latest: 0, stdout: 0, stderr: 0 };
      if (event.event_seq !== state.latest + 1) throw new Error('Unexpected live event sequence');
      if (state.result) throw new Error('Execution event arrived after its terminal event');
      state.latest = event.event_seq;
      for (const stream of ['stdout', 'stderr']) {
        if (event.type !== `execution.${stream}`) continue;
        if (event.encoding !== 'base64' || !event.data.startsWith('base64:')) throw new Error('Invalid output encoding');
        const bytes = Buffer.from(event.data.slice(7), 'base64');
        if (bytes.length > 65536 || event.stream_offset !== state[stream]) throw new Error('Invalid output chunk');
        state[stream] += bytes.length;
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
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      if (this.failure) throw this.failure;
      const state = this.executions.get(executionId);
      if (state && predicate(state)) return state;
      if (state?.result) throw new Error(`Execution ended before expected progress: ${state.result.error?.code ?? `exit ${state.result.exit_code}`}; stdout_bytes=${state.stdout}; stderr_bytes=${state.stderr}`);
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
    console.log(JSON.stringify({ execution_id: id, status: result.status, stdout_bytes: result.stdout_bytes }));
  } finally { await client.close(); }
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
