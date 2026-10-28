const crypto = require('node:crypto');
const { normalizeServer, validateCommand, snapshot } = require('./core.cjs');

class Service {
  constructor(store, ssh, emit) { this.store = store; this.ssh = ssh; this.emit = emit; this.requests = new Map(); this.jobs = new Map(); this.aiEnabled = false; }
  changed() { this.emit('changed', {}); }
  state() { return { servers: this.store.all(), requests: [...this.requests.values()], jobs: [...this.jobs.values()].map(j => this.jobView(j)), audit: this.store.history(), aiEnabled: this.aiEnabled }; }
  jobView(job) { const { controller, targets, targetControllers, controls, ...safe } = job; return safe; }
  setAI(enabled) {
    this.aiEnabled = !!enabled;
    if (!enabled) for (const req of this.requests.values()) if (req.status === 'pending') req.status = 'rejected';
    this.store.audit(enabled ? 'ai.enabled' : 'ai.disabled', 'Local MCP access'); this.changed();
  }
  plan(input) {
    const command = validateCommand(input.command);
    if (!Array.isArray(input.serverIds) || !input.serverIds.length || input.serverIds.length > 24 || new Set(input.serverIds).size !== input.serverIds.length) throw new Error('Select 1–24 distinct servers');
    const timeout = input.timeout === undefined ? 60 : Number(input.timeout);
    if (!Number.isInteger(timeout) || timeout < 5 || timeout > 600) throw new Error('Timeout must be 5–600 seconds');
    const targets = input.serverIds.map(id => this.store.get(id));
    targets.forEach(s => this.ssh.authorize?.(s, 'exec'));
    if (input.interactive !== undefined && typeof input.interactive !== 'boolean') throw new Error('Invalid interactive mode');
    return { command, timeout, interactive: input.interactive === true, serverIds: targets.map(s => s.id), serverNames: targets.map(s => `${s.name} (${s.username}@${s.host}:${s.port})`), fingerprints: targets.map(s => this.ssh.securitySnapshot ? this.ssh.securitySnapshot(s) : snapshot(s)) };
  }
  request(type, data) {
    if (!this.aiEnabled) throw new Error('AI access is disabled in Connector');
    if ([...this.requests.values()].filter(r => r.status === 'pending').length >= 20) throw new Error('Too many pending requests');
    let payload;
    if (type === 'execution') payload = this.plan(data);
    else if (type === 'add') {
      if (data.auth && data.auth !== 'agent') throw new Error('AI can add SSH-agent profiles only. Configure other credentials in the app.');
      payload = normalizeServer({ ...data, auth: 'agent', keyPath: '' });
    } else if (type === 'update') {
      const current = this.store.get(data.serverId);
      const allowed = ['name', 'host', 'port', 'username', 'group'];
      if (!data.changes || !Object.keys(data.changes).length || Object.keys(data.changes).some(k => !allowed.includes(k))) throw new Error('Specify name, host, port, username or group changes');
      if (current.auth !== 'agent' && ['host', 'port', 'username'].some(k => k in data.changes)) throw new Error('Edit connection endpoints for password/key profiles in the desktop app to protect credentials. AI can change name/group.');
      const normalized = normalizeServer({ ...current, ...data.changes }, current.id);
      const changes = Object.fromEntries(Object.keys(data.changes).map(k => [k, normalized[k]]));
      payload = { serverId: current.id, name: current.name, changes, fingerprint: snapshot(current) };
    } else if (type === 'remove') { const s = this.store.get(data.serverId); payload = { serverId: s.id, name: s.name, fingerprint: snapshot(s) }; }
    else throw new Error('Unknown request type');
    while (this.requests.size >= 100) {
      const old = [...this.requests.values()].find(r => r.status !== 'pending');
      if (!old) throw new Error('Request limit reached'); this.requests.delete(old.id);
    }
    const req = { id: crypto.randomUUID(), type, payload, status: 'pending', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString() };
    this.requests.set(req.id, req); this.store.audit('ai.requested', `${type}: ${req.id}`); this.changed(); return req;
  }
  async decide(id, approve) {
    const req = this.requests.get(id);
    if (!req || req.status !== 'pending') throw new Error('Request is no longer pending');
    if (Date.now() > Date.parse(req.expiresAt)) { req.status = 'expired'; this.changed(); throw new Error('Request expired; ask AI for a new request'); }
    if (!approve || !this.aiEnabled) { req.status = 'rejected'; this.store.audit('ai.rejected', id); this.changed(); return; }
    req.status = 'processing';
    try {
      if (req.type === 'execution') {
        const p = req.payload;
        if (p.serverIds.some((sid, i) => (this.ssh.securitySnapshot ? this.ssh.securitySnapshot(this.store.get(sid)) : snapshot(this.store.get(sid))) !== p.fingerprints[i])) throw new Error('A target or route changed. Ask AI for a new plan.');
        req.jobId = this.run(p).id;
      } else if (req.type === 'add') req.serverId = this.store.put(req.payload).id;
      else if (req.type === 'update') {
        const current = this.store.get(req.payload.serverId);
        if (snapshot(current) !== req.payload.fingerprint) throw new Error('Server changed. Ask AI for a new request.');
        this.store.put({ ...current, ...req.payload.changes, secret: '' }, current.id);
      }
      else if (req.type === 'remove') {
        if (snapshot(this.store.get(req.payload.serverId)) !== req.payload.fingerprint) throw new Error('Server changed. Ask AI for a new request.');
        this.store.remove(req.payload.serverId);
      }
      req.status = 'approved'; this.store.audit('ai.approved', id);
    } catch (error) { req.status = 'failed'; req.error = error.message; throw error; }
    finally { this.changed(); }
  }
  run(input) {
    if ([...this.jobs.values()].some(j => j.status === 'running')) throw new Error('Another batch is running. Wait or cancel it first.');
    const plan = this.plan(input);
    while (this.jobs.size >= 20) this.jobs.delete(this.jobs.keys().next().value);
    const targets = plan.serverIds.map(id => this.store.get(id));
    const job = { id: crypto.randomUUID(), command: plan.command, timeout: plan.timeout, interactive: plan.interactive, createdAt: new Date().toISOString(), status: 'running', controller: new AbortController(), targets,
      targetControllers: new Map(targets.map(s => [s.id, new AbortController()])), controls: new Map(),
      results: targets.map(s => ({ serverId: s.id, name: s.name, status: 'queued', stdout: '', stderr: '', terminal: '', exitCode: null, removed: false })) };
    this.jobs.set(job.id, job); this.store.audit('batch.started', `${job.id}: ${targets.length} targets`); this.changed();
    let cursor = 0;
    const worker = async () => {
      while (cursor < targets.length) {
        const i = cursor++, result = job.results[i];
        const targetController = job.targetControllers.get(result.serverId);
        if (targetController.signal.aborted) { result.status = 'cancelled'; this.emit('job', this.jobView(job)); continue; }
        result.status = 'connecting'; this.emit('job', this.jobView(job));
        try {
          const current = this.store.get(result.serverId);
          if ((this.ssh.securitySnapshot ? this.ssh.securitySnapshot(current) : snapshot(current)) !== plan.fingerprints[i]) throw new Error('Target or route changed while queued. Review a new execution plan.');
          const end = await this.ssh.exec(targets[i], job.command, job.timeout, targetController.signal, (chunk, stderr) => {
            if (targetController.signal.aborted) return;
            result[stderr ? 'stderr' : 'stdout'] += chunk; result.terminal += chunk;
            this.emit('job-output', { jobId: job.id, serverId: result.serverId, data: chunk, stderr });
          }, { interactive: job.interactive, onReady: control => {
            if (targetController.signal.aborted) return;
            job.controls.set(result.serverId, control); result.status = 'running'; this.emit('job', this.jobView(job));
          } });
          Object.assign(result, end);
        } catch (error) { result.status = targetController.signal.aborted ? 'cancelled' : 'failed'; result.error = error.message; }
        finally { job.controls.delete(result.serverId); }
        if (targetController.signal.aborted) result.status = 'cancelled';
        this.emit('job', this.jobView(job));
      }
    };
    Promise.all(Array.from({ length: Math.min(4, targets.length) }, worker)).then(() => {
      job.status = job.controller.signal.aborted ? 'cancelled' : 'completed'; job.finishedAt = new Date().toISOString();
      this.store.audit('batch.finished', `${job.id}: ${job.status}`); this.emit('job', this.jobView(job)); this.changed();
    });
    return this.jobView(job);
  }
  cancel(id) { const job = this.jobs.get(id); if (job?.status === 'running') { job.controller.abort(); for (const c of job.targetControllers.values()) c.abort(); this.store.audit('batch.cancelled', id); } }
  cancelTarget(id, serverId, remove = false) {
    const job = this.jobs.get(id), result = job?.results.find(r => r.serverId === serverId);
    if (!result) throw new Error('Batch target not found');
    if (['queued', 'connecting', 'running', 'cancelling'].includes(result.status)) {
      result.status = result.status === 'queued' ? 'cancelled' : 'cancelling';
      job.targetControllers.get(serverId).abort(); job.controls.delete(serverId);
      this.store.audit('batch.target.cancelled', `${id}: ${result.name}`);
    }
    if (remove) result.removed = true;
    this.emit('job', this.jobView(job));
  }
  writeInput(id, serverIds, data) {
    const job = this.jobs.get(id);
    if (!job || job.status !== 'running' || !job.interactive) throw new Error('Interactive batch is not running');
    if (!Array.isArray(serverIds) || !serverIds.length || serverIds.length > 24 || new Set(serverIds).size !== serverIds.length) throw new Error('Select distinct active terminals');
    if (typeof data !== 'string' || !data.length || Buffer.byteLength(data) > 65536) throw new Error('Invalid terminal input');
    const controls = serverIds.map(serverId => {
      const result = job.results.find(r => r.serverId === serverId);
      const control = job.controls.get(serverId);
      if (!result || result.removed || result.status !== 'running' || !control || job.targetControllers.get(serverId).signal.aborted) throw new Error('A selected terminal is no longer active');
      return control;
    });
    for (const control of controls) control.write(data);
  }
  resizeTarget(id, serverId, cols, rows) { this.jobs.get(id)?.controls.get(serverId)?.resize(cols, rows); }
  shutdown() { for (const job of this.jobs.values()) this.cancel(job.id); this.ssh.closeAll(); }
}
module.exports = { Service };
