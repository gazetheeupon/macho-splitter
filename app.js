const $ = (id) => document.getElementById(id);

let currentBuffer = null;
let currentBaseName = 'universal';

function setStatus(msg, isWarn) {
  const el = $('status');
  el.textContent = msg || '';
  el.classList.toggle('warn', !!isWarn);
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function row(label, valueHtml) {
  return `<tr><td>${escapeHtml(label)}</td><td>${valueHtml}</td></tr>`;
}

function showError(msg) {
  $('errorCard').classList.remove('hidden');
  $('errorText').textContent = msg;
  $('resultsCard').classList.add('hidden');
}

function clearError() {
  $('errorCard').classList.add('hidden');
}

function fmtBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 2 : 0)} ${units[i]}`;
}

function download(filename, arrayBuffer) {
  const blob = new Blob([arrayBuffer], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function renderThinFile(parsed) {
  $('resultsCard').classList.remove('hidden');
  const t = parsed.thin;
  if (t.error) {
    $('summaryBanner').innerHTML = `<div class="banner bad"><strong>Could not read this file's Mach-O header</strong>${escapeHtml(t.error)}</div>`;
    $('archList').innerHTML = '';
    $('warningsList').innerHTML = '';
    return;
  }
  $('summaryBanner').innerHTML = `<div class="banner neutral"><strong>Already single-architecture</strong>This file is a plain (non-fat) Mach-O binary &mdash; it contains exactly one architecture, so there's nothing to split out.</div>`;
  let rows = '';
  rows += row('Architecture', escapeHtml(t.cputypeName ? (t.cpusubtypeName || t.cputypeName) : t.cputypeHex));
  rows += row('File type', escapeHtml(t.filetypeName || `0x${t.filetype.toString(16)}`));
  rows += row('Word size', t.is64 ? '64-bit' : '32-bit');
  rows += row('Load commands', String(t.ncmds));
  $('archList').innerHTML = `<div class="arch-block"><h3>The whole file</h3><table class="kv">${rows}</table></div>`;
  $('warningsList').innerHTML = '';
}

function renderFatFile(buffer, parsed) {
  $('resultsCard').classList.remove('hidden');
  const kind = parsed.is64BitOffsets ? 'FAT_MAGIC_64 (64-bit offset/size fields)' : 'FAT_MAGIC (32-bit offset/size fields)';
  $('summaryBanner').innerHTML = `<div class="banner good"><strong>${parsed.nfatArch} architecture${parsed.nfatArch === 1 ? '' : 's'} found</strong>${escapeHtml(kind)}, ${fmtBytes(parsed.fileSize)} total.</div>`;

  $('archList').innerHTML = parsed.architectures
    .map((a) => {
      const label = MachOFatSplitter.describeArch(a);
      let rows = '';
      rows += row('CPU type', `${escapeHtml(a.cputypeName || '(unknown)')} <code>${escapeHtml(a.cputypeHex)}</code>`);
      rows += row('CPU subtype', `${escapeHtml(a.cpusubtypeName || '(unknown)')} <code>0x${(a.cpusubtype >>> 0).toString(16)}</code>`);
      rows += row('Offset', `${a.offset.toLocaleString()} <span style="color:var(--muted)">(0x${a.offset.toString(16)})</span>`);
      rows += row('Size', `${a.size.toLocaleString()} bytes (${fmtBytes(a.size)})`);
      rows += row('Alignment', `2<sup>${a.align}</sup> = ${a.alignBytes.toLocaleString()} bytes`);
      if (a.thin && !a.thin.error) {
        rows += row('Slice file type', escapeHtml(a.thin.filetypeName || `0x${a.thin.filetype.toString(16)}`));
      }
      let warn = '';
      if (a.warning) warn = `<p class="arch-warn">${escapeHtml(a.warning)}</p>`;
      else if (a.thin && a.thin.error) warn = `<p class="arch-warn">Could not read this slice's own Mach-O header: ${escapeHtml(a.thin.error)}</p>`;
      else if (a.thin && a.thin.mismatchWarning) warn = `<p class="arch-warn">${escapeHtml(a.thin.mismatchWarning)}</p>`;
      const canExtract = !a.warning;
      const btn = canExtract ? `<button class="extract-btn" data-extract-index="${a.index}">Extract ${escapeHtml(label)} as a standalone file</button>` : '';
      return `<div class="arch-block"><h3>${escapeHtml(label)}</h3><table class="kv">${rows}</table>${warn}${btn}</div>`;
    })
    .join('');

  $('archList').querySelectorAll('[data-extract-index]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const idx = Number(btn.getAttribute('data-extract-index'));
      const entry = parsed.architectures[idx];
      try {
        const sliceBuf = MachOFatSplitter.extractSlice(buffer, entry);
        const label = MachOFatSplitter.describeArch(entry).replace(/[^a-zA-Z0-9_.-]+/g, '_');
        download(`${currentBaseName}.${label}`, sliceBuf);
      } catch (e) {
        setStatus(e.message, true);
      }
    });
  });

  $('warningsList').innerHTML = parsed.warnings.length
    ? `<h3>Notes</h3><ul style="font-size:.85rem;color:var(--warn);padding-left:1.2rem;">${parsed.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join('')}</ul>`
    : '';
}

async function handleFile(file) {
  clearError();
  $('fname').textContent = file.name;
  setStatus('Reading file…');
  $('resultsCard').classList.add('hidden');
  currentBaseName = file.name.replace(/\.[^.]+$/, '') || 'universal';
  try {
    const buffer = await file.arrayBuffer();
    currentBuffer = buffer;
    const parsed = MachOFatSplitter.parseMachO(buffer);
    setStatus(`Loaded ${file.name} (${fmtBytes(buffer.byteLength)}).`);
    if (parsed.isFat) {
      renderFatFile(buffer, parsed);
    } else {
      renderThinFile(parsed);
    }
  } catch (err) {
    setStatus('', false);
    showError((err && err.message) || String(err));
  }
}

function bindDrop() {
  const dz = $('dropzone');
  const input = $('fileInput');
  const setDrag = (on) => dz.classList.toggle('drag', on);
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); setDrag(true); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); setDrag(false); }));
  dz.addEventListener('drop', (e) => {
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  dz.addEventListener('click', () => input.click());
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  input.addEventListener('change', () => {
    if (input.files && input.files[0]) handleFile(input.files[0]);
    input.value = '';
  });
}

bindDrop();
