import { SerializeAddon } from '@xterm/addon-serialize';

// Keep paste inside xterm so bracketed paste and the existing broadcast/input
// handlers behave exactly as they do for keyboard input.
export function attachTerminalClipboard(term, element) {
  const serialize = new SerializeAddon();
  term.loadAddon(serialize);
  let timer, disposed = false;
  const copy = () => {
    const text = term.getSelection();
    if (!text) return;
    window.connector.copyTerminal({ text, html: serialize.serializeAsHTML({ onlySelection: true, includeGlobalBackground: true }) }).catch(console.error);
  };
  const selection = term.onSelectionChange(() => {
    clearTimeout(timer);
    if (term.hasSelection()) timer = setTimeout(copy, 80);
  });
  const paste = async event => {
    event.preventDefault();
    // Do not paste from remote mouse-reporting escape sequences: only a local
    // contextmenu gesture reaches this handler.
    if (term.options.disableStdin) return;
    try {
      const text = await window.connector.readTerminalClipboard();
      if (!disposed && !term.options.disableStdin && text) { term.focus(); term.paste(text); }
    } catch (error) { console.error(error); }
  };
  element.addEventListener('contextmenu', paste);
  const finishSelection = event => { if (event.button === 0) { clearTimeout(timer); copy(); } };
  element.addEventListener('mouseup', finishSelection);
  const nativeCopy = event => { if (term.hasSelection()) { event.preventDefault(); clearTimeout(timer); copy(); } };
  element.addEventListener('copy', nativeCopy, true);
  return () => { disposed = true; clearTimeout(timer); selection.dispose(); element.removeEventListener('contextmenu', paste); element.removeEventListener('mouseup', finishSelection); element.removeEventListener('copy', nativeCopy, true); };
}

export function sendTerminalInput(send, data) {
  // Every chunk stays below the backend's 64 KiB UTF-8 input bound. Avoid
  // splitting a surrogate pair, while preserving bracketed-paste sequences.
  for (let start = 0; start < data.length;) {
    let end = Math.min(start + 12000, data.length);
    if (end < data.length && /[\uD800-\uDBFF]/.test(data[end - 1])) end--;
    send(data.slice(start, end)); start = end;
  }
}
