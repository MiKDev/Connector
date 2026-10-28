import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { attachTerminalClipboard, sendTerminalInput } from './terminal-clipboard';
import { Server, Square, X, Send, CornerDownLeft } from 'lucide-react';

const api = window.connector;
const activeStatuses = ['queued', 'connecting', 'running', 'cancelling'];
function BatchTerminal({ job, result, attempt }) {
  const mount = useRef(null), instance = useRef(null), written = useRef(''), send = useRef(null);
  send.current = data => { if (result.status === 'running' && !result.removed) attempt(() => api.writeBatch(job.id, [result.serverId], data)); };
  useEffect(() => {
    const term = new Terminal({ fontSize: 12, cursorBlink: true, scrollback: 3000, fontFamily: 'Consolas, "Liberation Mono", monospace', theme: { background: '#0b111b', foreground: '#c5d2e5', cursor: '#b1a4f0' }, disableStdin: false });
    const fit = new FitAddon(); term.loadAddon(fit); term.open(mount.current); instance.current = term;
    const detachClipboard = attachTerminalClipboard(term, mount.current);
    const data = term.onData(value => sendTerminalInput(chunk => send.current(chunk), value));
    const observer = new ResizeObserver(() => {
      if (!mount.current?.offsetWidth) return;
      fit.fit(); api.resizeBatch(job.id, result.serverId, term.cols, term.rows).catch(() => {});
    });
    observer.observe(mount.current);
    return () => { detachClipboard(); observer.disconnect(); data.dispose(); term.dispose(); instance.current = null; written.current = ''; };
  }, [job.id, result.serverId]);
  useEffect(() => {
    const output = result.terminal || '';
    if (instance.current && output !== written.current) {
      if (!output.startsWith(written.current)) instance.current.reset();
      instance.current.write(output.startsWith(written.current) ? output.slice(written.current.length) : output);
      written.current = output;
    }
  }, [result.terminal]);
  useEffect(() => { if (instance.current) instance.current.options.disableStdin = result.status !== 'running'; }, [result.status]);
  return <div className="batch-terminal" aria-label={`Interactive terminal ${result.name}`} ref={mount}/>;
}
function LineInput({ label, disabled, onSend, count }) {
  const [value, setValue] = useState('');
  return <form className="batch-input" onSubmit={async e => { e.preventDefault(); if (disabled || !value.length) return; await onSend(value + '\r'); setValue(''); }}>
    <CornerDownLeft size={14}/><input aria-label={label} autoComplete="off" spellCheck={false} placeholder={count ? `Input to ${count} active terminals, e.g. y` : 'Reply to this terminal, e.g. y'} value={value} onChange={e => setValue(e.target.value)} disabled={disabled}/>
    <button type="button" className="button small" disabled={disabled} onClick={() => onSend('\x03')}>Ctrl+C</button>
    <button className="button small" type="submit" disabled={disabled || !value.length}><Send size={12}/>Send Enter{count ? ` (${count})` : ''}</button>
  </form>;
}
export function JobCard({ job, attempt, onRemove }) {
  const visible = job.results.filter(r => !r.removed), live = visible.filter(r => r.status === 'running');
  const [targets, setTargets] = useState([]);
  const [allLive, setAllLive] = useState(true);
  const sendIds = allLive ? live.map(r => r.serverId) : live.filter(r => targets.includes(r.serverId)).map(r => r.serverId);
  const send = (ids, data) => attempt(() => api.writeBatch(job.id, ids, data));
  const badge = status => <span className={`badge ${status === 'succeeded' ? 'green' : ['failed','timed-out','disconnected'].includes(status) ? 'red' : status === 'running' ? 'purple' : ''}`}>{status}</span>;
  return <section className="panel job-panel" data-job-id={job.id}>
    <div className="job-heading"><div><code>{job.command}</code><span>{new Date(job.createdAt).toLocaleTimeString()} · {visible.length}/{job.results.length} targets · {job.timeout}s timeout · {job.interactive ? 'Interactive PTY' : 'Command output'}</span></div>{badge(job.status)}{job.status === 'running' && <button className="button small danger" onClick={() => attempt(() => api.cancelBatch(job.id))}><Square size={12}/>Cancel batch</button>}</div>
    {job.interactive && job.status === 'running' && <div className="batch-broadcast">
      <label><input type="checkbox" checked={allLive} onChange={e => setAllLive(e.target.checked)}/>Send to all active terminals</label>
      {!allLive && <div className="batch-input-targets">{live.map(r => <label key={r.serverId}><input type="checkbox" checked={targets.includes(r.serverId)} onChange={() => setTargets(s => s.includes(r.serverId) ? s.filter(id => id !== r.serverId) : [...s, r.serverId])}/>{r.name}</label>)}</div>}
      <LineInput label="Input to batch terminals" count={sendIds.length} disabled={!sendIds.length} onSend={data => send(sendIds, data)}/>
      <span className="muted">Input goes only to the listed active targets. Queued, cancelled and removed targets receive nothing.</span>
    </div>}
    <div className="batch-results">{visible.map(r => <section className="result" data-server-id={r.serverId} key={r.serverId}>
      <div className="result-heading"><Server size={14}/><strong>{r.name}</strong>{badge(r.status)}{r.exitCode !== null && <span>exit {r.exitCode}</span>}
        {activeStatuses.includes(r.status) && <button className="button small danger" disabled={r.status === 'cancelling'} onClick={() => attempt(() => api.cancelBatchTarget(job.id, r.serverId))}>Cancel server</button>}
        <button className="icon-button danger-hover" title={activeStatuses.includes(r.status) ? 'Cancel and remove this target' : 'Remove this result'} aria-label={`Remove ${r.name} from batch`} onClick={() => onRemove(job.id, r.serverId)}><X size={14}/></button>
      </div>
      {job.interactive ? <><BatchTerminal job={job} result={r} attempt={attempt}/><LineInput label={`Input to ${r.name}`} disabled={r.status !== 'running'} onSend={data => send([r.serverId], data)}/></> : <pre>{r.stdout}{r.stderr ? `\n[stderr]\n${r.stderr}` : ''}{!r.stdout && !r.stderr && !r.error ? 'Waiting for output…' : ''}</pre>}
      {r.error && <div className="result-error">{r.error}</div>}{r.truncated && <div className="inline-note">Output capped at 256 KiB for this target.</div>}
    </section>)}</div>
    {!visible.length && <div className="quiet-empty">All targets were removed from this batch.</div>}
    <div className="inline-note">Cancel requests termination and closes this target’s connection. Remote processes may continue. Removed results stay in the session history.</div>
  </section>;
}
