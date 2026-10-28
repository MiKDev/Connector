import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Folder, File, Link2, ArrowUp, Home, RefreshCw, FolderOpen, FolderPlus, ArrowRight, ArrowLeft, HardDrive, Network, X, Plug, ShieldCheck, Square } from 'lucide-react';
import './files.css';
const api = window.connector;
const emptyPane = serverId => ({ serverId, endpoint: null, path: '', parent: '', entries: [], names: [], busy: false, error: '' });
export function formatBytes(value = 0) { if (value < 1024) return `${value} B`; const unit = Math.min(4, Math.floor(Math.log(value) / Math.log(1024))); return `${(value / 1024 ** unit).toFixed(1)} ${['B','KiB','MiB','GiB','TiB'][unit]}`; }
function FilePane({ pane, label, servers, onOpen, onBrowse, onSelect, onFolder, onDisconnect, onLocalFolder }) {
  const [pathValue, setPathValue] = useState(''), [folderName, setFolderName] = useState(''), [creating, setCreating] = useState(false);
  // Synchronize before the enabled field is painted, so a completed listing
  // cannot overwrite a folder path the user has just started entering.
  useLayoutEffect(() => setPathValue(pane.path), [pane.path]);
  const selectable = pane.entries.filter(e => ['file','folder'].includes(e.kind));
  const allSelected = selectable.length > 0 && selectable.every(e => pane.names.includes(e.name));
  return <section className="panel file-pane" aria-label={`${label} file pane`}>
    <div className="file-pane-heading"><span>{label === 'Left' ? 'SOURCE / DESTINATION' : 'DESTINATION / SOURCE'}</span><span className="badge">{pane.endpoint?.local ? 'Local disk' : 'SFTP'}</span></div>
    <div className="file-endpoint"><HardDrive size={16}/><select aria-label={`${label} endpoint`} value={pane.serverId} disabled={pane.busy} onChange={e => onOpen(e.target.value)}><option value="">Choose an endpoint…</option><option value="local">This computer</option>{[...new Set(servers.map(s => s.group))].sort().map(group => <optgroup label={group} key={group}>{servers.filter(s => s.group === group).map(s => <option key={s.id} value={s.id}>{s.name} · {s.host}</option>)}</optgroup>)}</select>{pane.endpoint && !pane.endpoint.local && <button className="icon-button" aria-label={`Disconnect ${label} file pane`} disabled={pane.busy} onClick={onDisconnect}><X size={15}/></button>}</div>
    <form className="file-path" onSubmit={e => { e.preventDefault(); onBrowse(pathValue); }}><button type="button" className="icon-button" aria-label={`${label} parent folder`} disabled={!pane.endpoint || pane.busy} onClick={() => onBrowse(pane.parent)}><ArrowUp size={15}/></button><input aria-label={`${label} folder path`} placeholder="Absolute folder path" value={pathValue} disabled={!pane.endpoint || pane.busy} onChange={e => setPathValue(e.target.value)}/><button className="button small" type="submit" disabled={!pane.endpoint || pane.busy}>Go</button></form>
    <div className="file-tools"><button className="icon-button" aria-label={`${label} home folder`} disabled={!pane.endpoint || pane.busy} onClick={() => onBrowse(pane.endpoint.home)}><Home size={15}/></button><button className="icon-button" aria-label={`Refresh ${label} files`} disabled={!pane.endpoint || pane.busy} onClick={() => onBrowse(pane.path)}><RefreshCw size={15}/></button>{pane.endpoint?.local && <button className="icon-button" aria-label={`Choose ${label} local folder`} disabled={pane.busy} onClick={onLocalFolder}><FolderOpen size={15}/></button>}<button className="icon-button" aria-label={`New folder in ${label} pane`} disabled={!pane.endpoint || pane.busy} onClick={() => setCreating(s => !s)}><FolderPlus size={15}/></button><span>{pane.busy ? 'Loading…' : `${pane.entries.length} entries · ${pane.names.length} selected`}</span></div>
    {creating && <form className="new-folder" onSubmit={async e => { e.preventDefault(); if (await onFolder(folderName)) { setFolderName(''); setCreating(false); } }}><input aria-label={`${label} new folder name`} required placeholder="New folder name" value={folderName} onChange={e => setFolderName(e.target.value)}/><button className="button small" type="submit">Create</button><button className="icon-button" type="button" aria-label={`Cancel new folder in ${label} pane`} onClick={() => setCreating(false)}><X size={14}/></button></form>}
    {pane.error && <div className="file-error" role="alert">{pane.error}</div>}
    <div className="file-list-header"><input aria-label={`Select all ${label} files`} type="checkbox" checked={allSelected} disabled={!selectable.length || pane.busy} onChange={() => onSelect(allSelected ? [] : selectable.map(e => e.name))}/><span>NAME</span><span>SIZE</span></div>
    <div className="file-list">{pane.entries.map(entry => <div className={`file-entry ${pane.names.includes(entry.name) ? 'chosen' : ''}`} key={entry.name} onDoubleClick={() => { if (entry.kind === 'folder') onBrowse(pane.path.replace(/[\\/]$/, '') + (pane.endpoint.local && pane.path.includes('\\') ? '\\' : '/') + entry.name); }}>
      <input type="checkbox" aria-label={`${label} select ${entry.name}`} checked={pane.names.includes(entry.name)} disabled={!['folder','file'].includes(entry.kind) || pane.busy} onChange={() => onSelect(pane.names.includes(entry.name) ? pane.names.filter(n => n !== entry.name) : [...pane.names, entry.name])}/>
      <span className="file-name">{entry.kind === 'folder' ? <Folder size={16}/> : entry.kind === 'file' ? <File size={15}/> : <Link2 size={15}/>}<button title={entry.name} disabled={pane.busy || !['file', 'folder'].includes(entry.kind)} onClick={() => entry.kind === 'folder' ? onBrowse(pane.path.replace(/[\\/]$/, '') + (pane.endpoint.local && pane.path.includes('\\') ? '\\' : '/') + entry.name) : onSelect(pane.names.includes(entry.name) ? pane.names.filter(n => n !== entry.name) : [...pane.names, entry.name])}>{entry.name}</button></span><span className="file-size">{entry.kind === 'folder' ? 'Folder' : entry.kind === 'link' ? 'Link' : formatBytes(entry.size)}</span>
    </div>)}{!pane.entries.length && <div className="quiet-empty"><FolderOpen size={25}/><span>{pane.busy ? 'Reading folder…' : pane.endpoint ? 'This folder is empty.' : 'Choose a server to browse files.'}</span></div>}</div>
    <div className="file-pane-footer"><ShieldCheck size={12}/>{pane.endpoint?.local ? 'Local filesystem' : 'Saved credentials · pinned SSH host identity'}</div>
  </section>;
}
export function FilesView({ servers, visible, attempt }) {
  const [panes, setPanes] = useState([emptyPane('local'), emptyPane('')]);
  const [jobs, setJobs] = useState([]), [transferring, setTransferring] = useState(false);
  const current = useRef(panes), generation = useRef([0, 0]); current.current = panes;
  const update = (index, patch) => setPanes(old => old.map((pane, i) => i === index ? { ...pane, ...patch } : pane));
  const load = async (index, serverId, directory, existing) => {
    const ticket = ++generation.current[index]; update(index, { busy: true, error: '' });
    try {
      const endpoint = existing || await api.openFiles(serverId);
      const listing = await api.listFiles(endpoint.id, directory || endpoint.home);
      if (ticket === generation.current[index]) update(index, { serverId, endpoint, ...listing, names: [], busy: false });
    } catch (error) { if (ticket === generation.current[index]) update(index, { busy: false, error: error.message }); }
  };
  useEffect(() => { if (visible && !current.current[0].endpoint && !current.current[0].busy) load(0, 'local'); }, [visible]);
  useEffect(() => {
    api.fileState().then(setJobs).catch(() => {});
    return api.onEvent(event => {
      if (event.type !== 'transfer') return;
      const { type, ...job } = event;
      setJobs(old => old.some(j => j.id === job.id) ? old.map(j => j.id === job.id ? job : j) : [...old, job]);
      if (job.status !== 'running') current.current.forEach((pane, index) => { if (pane.endpoint && !pane.busy) load(index, pane.serverId, pane.path, pane.endpoint); });
    });
  }, []);
  const open = (index, id) => { if (!id) { generation.current[index]++; update(index, emptyPane('')); } else load(index, id); };
  const browse = (index, directory) => { const pane = current.current[index]; if (pane.endpoint) load(index, pane.serverId, directory, pane.endpoint); };
  const transfer = async index => {
    const source = current.current[index], destination = current.current[1 - index];
    if (!source.endpoint || !destination.endpoint) return;
    setTransferring(true);
    await attempt(async () => {
      const job = await api.transferFiles({ source: { endpointId: source.endpoint.id, path: source.path, names: source.names }, destination: { endpointId: destination.endpoint.id, path: destination.path } });
      if (job) setJobs(old => old.some(j => j.id === job.id) ? old : [...old, job]);
    });
    setTransferring(false);
  };
  const direct = panes.every(pane => pane.endpoint && !pane.endpoint.local);
  return <div className="files-view" style={{ display: visible ? 'block' : 'none' }}>
    <div className="page-heading"><div><div className="eyebrow">FILES BETWEEN YOUR SYSTEMS</div><h1>File transfer</h1><p>Browse two endpoints, select files or folders, then copy in either direction.</p></div><span className={`badge ${direct ? 'green' : ''}`}>{direct ? <Network size={13}/> : <HardDrive size={13}/>} {direct ? 'Direct server → server' : 'Host ↔ server'}</span></div>
    <div className="file-route-note"><ShieldCheck size={17}/><div>{direct ? <><strong>Direct server-to-server SFTP</strong><p>File bytes stay between the servers. Source requires Python 3 and OpenSSH 9+. Destination requires a saved password; the source borrows it in memory for this operation.</p></> : <><strong>Encrypted file transfer</strong><p>Select “This computer” for uploads/downloads, or two servers for direct transfer. Saved SSH credentials are reused. Existing files are never silently replaced.</p></>}</div></div>
    <div className="files-layout">{panes.map((pane, index) => <React.Fragment key={index}>{index === 1 && <div className="transfer-arrows"><button className="button primary" aria-label="Copy left to right" disabled={transferring || !panes[0].names.length || !panes[1].endpoint || panes.some(p => p.busy)} onClick={() => transfer(0)}><ArrowRight size={20}/></button><button className="button" aria-label="Copy right to left" disabled={transferring || !panes[1].names.length || !panes[0].endpoint || panes.some(p => p.busy)} onClick={() => transfer(1)}><ArrowLeft size={20}/></button></div>}<FilePane pane={pane} label={index === 0 ? 'Left' : 'Right'} servers={servers} onOpen={id => open(index, id)} onBrowse={directory => browse(index, directory)} onSelect={names => update(index, { names })} onFolder={name => attempt(async () => { await api.makeDirectory(pane.endpoint.id, pane.path, name); await load(index, pane.serverId, pane.path, pane.endpoint); return true; })} onLocalFolder={() => attempt(async () => { const directory = await api.chooseLocalFolder(); if (directory) browse(index, directory); })} onDisconnect={() => attempt(async () => { await api.closeFiles(pane.endpoint.id); generation.current[index]++; update(index, emptyPane('')); })}/></React.Fragment>)}</div>
    <div className="section-heading"><div><h2>Transfers</h2><p>{transferring ? 'Preparing file list and confirmation…' : 'Progress, completed files, and cancellation for each copy operation.'}</p></div></div>
    {!jobs.length && <div className="panel quiet-empty"><Plug size={24}/><span>Your transfers will appear here.</span></div>}
    {[...jobs].reverse().map(job => <section className="panel transfer-job" key={job.id}><div className="transfer-job-heading"><div><strong>{job.source} <ArrowRight size={13}/> {job.destination}</strong><span>{job.route === 'direct' ? 'DIRECT SFTP · file bytes bypass this computer' : 'Host / server stream'} · {job.filesDone}/{job.filesTotal} files · {formatBytes(job.bytes)} / {formatBytes(job.totalBytes)}</span></div><span className={`badge ${job.status === 'completed' ? 'green' : job.status === 'failed' ? 'red' : ''}`}>{job.status}</span>{job.status === 'running' && <button className="button small danger" onClick={() => attempt(() => api.cancelTransfer(job.id))}><Square size={12}/>Cancel transfer</button>}</div><progress max={job.totalBytes || 1} value={job.status === 'completed' ? job.totalBytes || 1 : Math.min(job.bytes, job.totalBytes)}/><code>{job.current || job.destinationPath}</code>{job.error && <p className="error-text">{job.error}</p>}{job.partialPaths?.length > 0 && <p className="error-text">Could not clean incomplete files: {job.partialPaths.join(', ')}</p>}{job.status === 'cancelled' && <p className="muted">Completed files and created folders remain. Incomplete files are removed where possible.</p>}</section>)}
  </div>;
}
