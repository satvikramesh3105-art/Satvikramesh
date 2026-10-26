const $ = (selector) => document.querySelector(selector);
const fileInput = $('#file-input');
const manifestInput = $('#manifest-input');
const backupInput = $('#backup-input');
const fileResult = $('#file-result');
let selectedFile = null;
let selectedManifest = null;
let selectedBackup = null;
let lastEncryptedBlob = null;
let lastEncryptedName = null;
let lastEncryptedManifest = null;
let toastTimer;

function toast(message) {
  const node = $('#toast');
  node.textContent = message;
  node.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove('show'), 2800);
}
function setFile(file) {
  selectedFile = file || null;
  $('#file-name').textContent = file ? `${file.name} · ${formatBytes(file.size)}` : 'No file selected';
  fileResult.className = 'result-box';
  fileResult.textContent = file ? 'File selected. Choose an action; contents remain in this browser.' : 'Choose a file, then select an action. Encrypted files download with the .sentinel extension.';
}
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(2)} MB`;
}
function bytesToHex(bytes) { return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
async function sha256Hex(buffer) {
  if (!window.isSecureContext || !window.crypto?.subtle) throw new Error('Browser Web Crypto requires HTTPS or localhost. Open the demo on the host machine or use HTTPS for a remote device.');
  return bytesToHex(await crypto.subtle.digest('SHA-256', buffer));
}
async function deriveKey(passphrase, salt) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function logEvent(type, details) {
  try {
    await fetch('/api/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type, details }) });
    await refreshAudit();
  } catch { /* Audit reporting must not interrupt local file operations. */ }
}
async function withBusy(button, operation) {
  button.disabled = true;
  try { await operation(); } catch (error) {
    fileResult.className = 'result-box error';
    fileResult.textContent = error.name === 'OperationError' ? 'Could not decrypt: wrong passphrase or damaged encrypted file.' : `Operation failed: ${error.message}`;
  } finally { button.disabled = false; }
}
$('#encrypt-btn').addEventListener('click', (event) => withBusy(event.currentTarget, async () => {
  if (!selectedFile) throw new Error('Select a file first.');
  const passphrase = $('#passphrase').value;
  if (passphrase.length < 8) throw new Error('Use a passphrase with at least 8 characters.');
  const plain = await selectedFile.arrayBuffer();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const metadata = new TextEncoder().encode(JSON.stringify({ v: 1, name: selectedFile.name, type: selectedFile.type || 'application/octet-stream' }));
  const header = new Uint8Array(4 + metadata.length + salt.length + iv.length);
  new DataView(header.buffer).setUint32(0, metadata.length);
  header.set(metadata, 4); header.set(salt, 4 + metadata.length); header.set(iv, 20 + metadata.length);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: header }, key, plain);
  const encryptedBlob = new Blob([header, ciphertext], { type: 'application/octet-stream' });
  const encryptedName = `${selectedFile.name}.sentinel`;
  lastEncryptedBlob = encryptedBlob;
  lastEncryptedName = encryptedName;
  const manifest = await SentinelMerkle.createManifest(await encryptedBlob.arrayBuffer(), encryptedName);
  lastEncryptedManifest = new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' });
  saveBlob(encryptedBlob, encryptedName);
  saveBlob(lastEncryptedManifest, `${encryptedName}.manifest.json`);
  const digest = await sha256Hex(plain);
  fileResult.className = 'result-box success';
  fileResult.textContent = `Encrypted locally with AES-256-GCM. Original SHA-256: ${digest}. Merkle root for the encrypted file: ${manifest.root}. Encrypted file and manifest downloaded separately.`;
  await logEvent('encrypt', { name: selectedFile.name, bytes: selectedFile.size, sha256: digest, merkle_root: manifest.root });
  toast('Encrypted file and its Merkle manifest downloaded. Keep both safe.');
}));
$('#decrypt-btn').addEventListener('click', (event) => withBusy(event.currentTarget, async () => {
  if (!selectedFile) throw new Error('Select a .sentinel file first.');
  const passphrase = $('#passphrase').value;
  if (!passphrase) throw new Error('Enter the passphrase used to encrypt this file.');
  const input = new Uint8Array(await selectedFile.arrayBuffer());
  if (input.length < 49) throw new Error('This file is too short to be a valid Sentinel encrypted file.');
  const metadataLength = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(0);
  const saltStart = 4 + metadataLength;
  const ivStart = saltStart + 16;
  if (metadataLength > 4096 || ivStart + 12 >= input.length) throw new Error('Invalid Sentinel file header.');
  const metadata = JSON.parse(new TextDecoder().decode(input.slice(4, saltStart)));
  if (metadata.v !== 1) throw new Error('Unsupported encrypted file version.');
  const key = await deriveKey(passphrase, input.slice(saltStart, ivStart));
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: input.slice(ivStart, ivStart + 12), additionalData: input.slice(0, ivStart + 12) }, key, input.slice(ivStart + 12));
  const digest = await sha256Hex(plaintext);
  saveBlob(new Blob([plaintext], { type: metadata.type || 'application/octet-stream' }), metadata.name || 'decrypted-file');
  fileResult.className = 'result-box success';
  fileResult.textContent = `Decrypted locally. Restored file SHA-256: ${digest}.`;
  await logEvent('decrypt', { name: metadata.name || 'file', bytes: plaintext.byteLength, sha256: digest });
  toast('File decrypted and downloaded.');
}));
$('#merkle-create-btn').addEventListener('click', (event) => withBusy(event.currentTarget, async () => {
  if (!selectedFile) throw new Error('Select a file first.');
  const manifest = await SentinelMerkle.createManifest(await selectedFile.arrayBuffer(), selectedFile.name);
  saveBlob(new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' }), `${selectedFile.name}.manifest.json`);
  fileResult.className = 'result-box success';
  fileResult.textContent = `Merkle manifest saved locally. Root: ${manifest.root}. Store the manifest separately from the file to make later tamper checks meaningful.`;
  await logEvent('integrity-check', { name: selectedFile.name, bytes: selectedFile.size, merkle_root: manifest.root, result: 'manifest-created' });
  toast('Merkle manifest downloaded. Keep it separate from the file.');
}));
$('#manifest-select-btn').addEventListener('click', () => manifestInput.click());
manifestInput.addEventListener('change', () => {
  selectedManifest = manifestInput.files[0] || null;
  $('#manifest-name').textContent = selectedManifest ? selectedManifest.name : 'No manifest selected';
});
$('#backup-select-btn').addEventListener('click', () => backupInput.click());
backupInput.addEventListener('change', () => {
  selectedBackup = backupInput.files[0] || null;
  $('#backup-name').textContent = selectedBackup ? `${selectedBackup.name} · ${formatBytes(selectedBackup.size)}` : 'No backup selected';
});
$('#merkle-verify-btn').addEventListener('click', (event) => withBusy(event.currentTarget, async () => {
  if (!selectedFile) throw new Error('Select the file to verify first.');
  if (!selectedManifest) throw new Error('Choose the saved JSON manifest for this file.');
  if (selectedManifest.size > 2 * 1024 * 1024) throw new Error('The selected manifest is unexpectedly large.');
  const manifest = JSON.parse(await selectedManifest.text());
  const result = await SentinelMerkle.verifyFile(await selectedFile.arrayBuffer(), manifest);
  fileResult.className = `result-box ${result.valid ? 'success' : 'error'}`;
  fileResult.textContent = result.valid ? `INTEGRITY VERIFIED. ${result.reason} Root: ${result.actualRoot}.` : `INTEGRITY MISMATCH. ${result.reason} Expected root: ${result.expectedRoot || 'invalid'}; calculated root: ${result.actualRoot || 'not calculated'}.`;
  await logEvent('integrity-check', { name: selectedFile.name, result: result.valid ? 'verified' : 'mismatch', merkle_root: result.actualRoot || 'unavailable' });
  toast(result.valid ? 'Merkle integrity verification passed.' : 'File does not match the selected manifest.');
}));
$('#recover-btn').addEventListener('click', (event) => withBusy(event.currentTarget, async () => {
  if (!selectedFile) throw new Error('Select the current file to check first.');
  if (!selectedBackup) throw new Error('Select a separate trusted backup file.');
  if (!selectedManifest) throw new Error('Choose the saved trusted manifest for the current file.');
  if (selectedManifest.size > 2 * 1024 * 1024) throw new Error('The selected manifest is unexpectedly large.');
  const manifest = JSON.parse(await selectedManifest.text());
  const current = await SentinelMerkle.verifyFile(await selectedFile.arrayBuffer(), manifest);
  if (current.valid) {
    fileResult.className = 'result-box success';
    fileResult.textContent = 'Current file passes the trusted Merkle manifest. No recovery copy was downloaded.';
    return;
  }
  const backup = await SentinelMerkle.verifyFile(await selectedBackup.arrayBuffer(), manifest);
  if (!backup.valid) {
    fileResult.className = 'result-box error';
    fileResult.textContent = `Recovery stopped: the backup does not match the trusted manifest. ${backup.reason}`;
    await logEvent('recovery', { current: selectedFile.name, backup: selectedBackup.name, result: 'backup-rejected' });
    return;
  }
  const originalName = manifest.fileName || selectedFile.name.replace(/\.tampered$/i, '');
  saveBlob(new Blob([await selectedBackup.arrayBuffer()], { type: selectedBackup.type || 'application/octet-stream' }), `${originalName}.recovered`);
  fileResult.className = 'result-box success';
  fileResult.textContent = `Current file failed its integrity check. The separate backup matched the trusted root and was downloaded as ${originalName}.recovered. The original was not overwritten.`;
  await logEvent('recovery', { current: selectedFile.name, backup: selectedBackup.name, result: 'verified-backup-downloaded', merkle_root: backup.actualRoot });
  toast('Verified backup downloaded; original file left unchanged.');
}));
$('#cloud-upload-btn').addEventListener('click', (event) => withBusy(event.currentTarget, async () => {
  if (!lastEncryptedBlob || !lastEncryptedName) throw new Error('Encrypt a file first. Only the encrypted artifact can be uploaded.');
  const field = $('#presigned-put-url');
  let destination;
  try { destination = new URL(field.value); } catch { throw new Error('Paste a valid provider-issued pre-signed URL.'); }
  if (destination.protocol !== 'https:') throw new Error('Cloud uploads require an HTTPS pre-signed URL.');
  if (destination.username || destination.password || destination.hash) throw new Error('URL credentials and fragments are not accepted. Use a provider-issued query-signed URL.');
  const response = await fetch(destination.href, {
    method: 'PUT',
    mode: 'cors',
    credentials: 'omit',
    redirect: 'error',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: lastEncryptedBlob,
  });
  if (!response.ok) throw new Error(`Object storage returned HTTP ${response.status}. Check URL expiry, signed headers, and bucket CORS configuration.`);
  fileResult.className = 'result-box success';
  fileResult.textContent = `Encrypted artifact uploaded directly to the configured storage provider. The Flask app did not receive the file or signed URL. Keep the matching Merkle manifest and passphrase separately.`;
  await logEvent('cloud-upload', { name: lastEncryptedName, bytes: lastEncryptedBlob.size, result: 'direct-upload-complete' });
  field.value = '';
  toast('Encrypted artifact uploaded directly to object storage.');
}));
async function refreshVault() {
  const status = $('#vault-status');
  const list = $('#vault-list');
  try {
    const response = await fetch('/api/vault/objects', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Local vault is unavailable.');
    status.textContent = 'Local MinIO vault ready · encrypted objects only';
    if (!data.objects.length) {
      list.textContent = 'No encrypted files uploaded yet.';
      return;
    }
    list.innerHTML = data.objects.map((item) => `
      <div class="vault-item">
        <span><b>${escapeHtml(item.name)}</b><small>${formatBytes(item.size)} · ${item.has_manifest ? 'manifest stored' : 'manifest missing'}</small></span>
        <button class="button text-button vault-download" type="button" data-object-id="${escapeHtml(item.id)}">Download</button>
      </div>`).join('');
    list.querySelectorAll('.vault-download').forEach((button) => {
      button.addEventListener('click', () => downloadVaultObject(button.dataset.objectId, button));
    });
  } catch (error) {
    status.textContent = error.message;
    list.textContent = 'Vault listing unavailable.';
  }
}
async function downloadVaultObject(objectId, button) {
  button.disabled = true;
  try {
    const response = await fetch(`/api/vault/objects/${encodeURIComponent(objectId)}/download-urls`, { cache: 'no-store' });
    const urls = await response.json();
    if (!response.ok) throw new Error(urls.error || 'Could not prepare the download.');
    const encryptedResponse = await fetch(urls.file_url, { cache: 'no-store' });
    if (!encryptedResponse.ok) throw new Error(`Encrypted-file download failed (HTTP ${encryptedResponse.status}).`);
    saveBlob(await encryptedResponse.blob(), urls.name);
    if (urls.manifest_url) {
      const manifestResponse = await fetch(urls.manifest_url, { cache: 'no-store' });
      if (!manifestResponse.ok) throw new Error(`Manifest download failed (HTTP ${manifestResponse.status}).`);
      saveBlob(await manifestResponse.blob(), `${urls.name}.manifest.json`);
    }
    toast('Encrypted file and available manifest downloaded.');
  } catch (error) {
    $('#vault-status').textContent = error.message;
  } finally {
    button.disabled = false;
  }
}
$('#vault-upload-btn').addEventListener('click', (event) => withBusy(event.currentTarget, async () => {
  if (!lastEncryptedBlob || !lastEncryptedName || !lastEncryptedManifest) {
    throw new Error('Encrypt a file first. Only the resulting ciphertext and its manifest can be uploaded.');
  }
  const response = await fetch('/api/vault/upload-urls', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: lastEncryptedName }),
  });
  const urls = await response.json();
  if (!response.ok) throw new Error(urls.error || 'Could not prepare a local-vault upload.');
  const fileResponse = await fetch(urls.file_url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: lastEncryptedBlob,
  });
  if (!fileResponse.ok) throw new Error(`Encrypted-file upload failed (HTTP ${fileResponse.status}).`);
  const manifestResponse = await fetch(urls.manifest_url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: lastEncryptedManifest,
  });
  if (!manifestResponse.ok) throw new Error(`Manifest upload failed (HTTP ${manifestResponse.status}); the encrypted file is stored but its manifest is missing.`);
  await logEvent('cloud-upload', { name: urls.name, bytes: lastEncryptedBlob.size, result: 'local-minio-upload-complete' });
  await refreshVault();
  toast('Encrypted file and integrity manifest stored in the local vault.');
}));
$('#vault-refresh-btn').addEventListener('click', refreshVault);
refreshVault();
fileInput.addEventListener('change', () => setFile(fileInput.files[0]));
const dropZone = $('#drop-zone');
dropZone.addEventListener('dragover', (event) => { event.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (event) => { event.preventDefault(); dropZone.classList.remove('dragover'); setFile(event.dataTransfer.files[0]); });
$('#toggle-pass').addEventListener('click', () => {
  const field = $('#passphrase');
  field.type = field.type === 'password' ? 'text' : 'password';
});
$('#request-count').addEventListener('input', (event) => { $('#request-count-label').textContent = event.target.value; });
$('#simulate-btn').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const response = await fetch('/api/shield/simulate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ count: Number($('#request-count').value) }) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Simulation failed');
    $('#allowed-count').textContent = result.allowed;
    $('#blocked-count').textContent = result.simulated_blocked;
    $('#shield-result').innerHTML = `<span class="shield-status-dot"></span><span>${result.allowed} allowed · ${result.simulated_blocked} simulated blocked. ${result.note}</span>`;
    await refreshAudit();
    toast('Safe local rate-limit simulation complete.');
  } catch (error) {
    $('#shield-result').textContent = error.message;
  } finally { button.disabled = false; }
});
$('.notice-close').addEventListener('click', () => $('.notice').remove());
$('#checkpoint-btn').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const response = await fetch('/api/audit/checkpoint', { cache: 'no-store' });
    if (!response.ok) throw new Error('Checkpoint export failed');
    const checkpoint = await response.json();
    if (!checkpoint.verified) throw new Error('Audit chain verification failed; checkpoint was not exported.');
    saveBlob(new Blob([JSON.stringify(checkpoint, null, 2)], { type: 'application/json' }), 'sentinel-audit-checkpoint.json');
    toast('Verified chain head exported. Store it outside this host.');
  } catch (error) {
    toast(error.message);
  } finally { button.disabled = false; }
});
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
async function refreshAudit() {
  const [auditResponse] = await Promise.all([fetch('/api/audit')]);
  const data = await auditResponse.json();
  const status = $('#chain-status');
  status.classList.toggle('invalid', !data.valid);
  status.innerHTML = `<i></i> ${data.valid ? 'Chain verified' : 'Chain invalid'}`;
  $('#ledger-status').textContent = data.valid ? 'Verified' : 'Attention';
  $('#ledger-count').textContent = `${data.events.length} recent event${data.events.length === 1 ? '' : 's'} · persistent local ledger`;
  const body = $('#audit-rows');
  if (!data.events.length) {
    body.innerHTML = '<tr><td colspan="4" class="empty-row">No activity yet. Encrypt a file or run a simulation to create an event.</td></tr>';
    return;
  }
  body.innerHTML = data.events.map((item) => {
    const detail = Object.entries(item.details).map(([key, value]) => `${key}: ${value}`).join(' · ') || '—';
    const time = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    return `<tr><td><span class="event-badge event-${escapeHtml(item.type)}">${escapeHtml(item.type.replace('-', ' '))}</span></td><td>${escapeHtml(detail)}</td><td>${escapeHtml(time)}</td><td class="hash-short" title="${escapeHtml(item.hash)}">${escapeHtml(item.hash.slice(0, 12))}…</td></tr>`;
  }).join('');
}
refreshAudit().catch(() => { $('#ledger-status').textContent = 'Offline'; $('#chain-status').textContent = 'Audit unavailable'; });

async function refreshSecurity() {
  try {
    const [metricsResponse, eventsResponse] = await Promise.all([
      fetch('/api/security/metrics', { cache: 'no-store' }),
      fetch('/api/security/events', { cache: 'no-store' }),
    ]);
    if (!metricsResponse.ok || !eventsResponse.ok) throw new Error('Security monitor unavailable');
    const metrics = await metricsResponse.json();
    const { events } = await eventsResponse.json();
    $('#live-request-count').innerHTML = `${metrics.requests_window} <small>/ ${metrics.window_seconds} sec</small>`;
    $('#live-block-count').textContent = `${metrics.blocked_10m} blocked · ${metrics.active_blocks} active IP block${metrics.active_blocks === 1 ? '' : 's'}`;
    $('#monitor-requests').textContent = metrics.requests_window;
    $('#monitor-window-label').textContent = `${metrics.window_seconds} SEC`;
    $('#monitor-blocked').textContent = metrics.blocked_10m;
    $('#monitor-active-blocks').textContent = metrics.active_blocks;
    $('#monitor-total-events').textContent = metrics.total_events;
    const modelStatus = metrics.anomaly_model ? `${metrics.anomaly_model === 'synthetic-demo' ? 'Synthetic demo' : 'Operator baseline'}${metrics.anomaly_alerts_10m ? ` · ${metrics.anomaly_alerts_10m} alert(s)` : ''}` : 'Not configured';
    $('#anomaly-model-status').textContent = modelStatus;
    const rows = $('#security-event-rows');
    if (!events.length) {
      rows.innerHTML = '<tr><td colspan="5" class="empty-row">No HTTP threats detected. Safe test patterns are covered in the automated suite.</td></tr>';
      return;
    }
    rows.innerHTML = events.map((item) => {
      const time = new Date(item.occurred_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      return `<tr><td>${escapeHtml(time)}</td><td>${escapeHtml(item.source_ip)}</td><td><span class="event-badge event-shield-test">${escapeHtml(item.rule)}</span></td><td>${escapeHtml(item.method)} ${escapeHtml(item.path)}</td><td>${escapeHtml(item.action)}</td></tr>`;
    }).join('');
  } catch {
    $('#live-block-count').textContent = 'Live monitor unavailable';
  }
}
refreshSecurity();
setInterval(refreshSecurity, 5000);
