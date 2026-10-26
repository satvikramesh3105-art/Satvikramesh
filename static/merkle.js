(() => {
  const CHUNK_SIZE = 1024 * 1024;
  const FANOUT = 4;
  const VERSION = 'sentinel-merkle-v1';

  function bytesToHex(bytes) {
    return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function hexToBytes(hex) {
    if (typeof hex !== 'string' || !/^(?:[0-9a-f]{2})+$/i.test(hex)) throw new Error('Invalid hash in Merkle manifest.');
    return Uint8Array.from(hex.match(/.{2}/g), (pair) => Number.parseInt(pair, 16));
  }

  async function sha256(bytes) {
    if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
      throw new Error('Browser Web Crypto requires HTTPS or localhost.');
    }
    return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
  }

  function concatenate(parts) {
    const length = parts.reduce((sum, part) => sum + part.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }

  async function createManifest(buffer, fileName) {
    const input = new Uint8Array(buffer);
    const leaves = [];
    const chunkCount = Math.max(1, Math.ceil(input.length / CHUNK_SIZE));
    for (let index = 0; index < chunkCount; index += 1) {
      const chunk = input.subarray(index * CHUNK_SIZE, Math.min((index + 1) * CHUNK_SIZE, input.length));
      const indexBytes = new Uint8Array(4);
      new DataView(indexBytes.buffer).setUint32(0, index);
      leaves.push(bytesToHex(await sha256(concatenate([Uint8Array.of(0), indexBytes, chunk]))));
    }

    let level = leaves.map(hexToBytes);
    while (level.length > 1) {
      const nextLevel = [];
      for (let offset = 0; offset < level.length; offset += FANOUT) {
        const children = level.slice(offset, offset + FANOUT);
        const header = new Uint8Array(5);
        header[0] = 1;
        new DataView(header.buffer).setUint32(1, children.length);
        nextLevel.push(await sha256(concatenate([header, ...children])));
      }
      level = nextLevel;
    }

    return {
      format: VERSION,
      algorithm: 'SHA-256',
      fanout: FANOUT,
      chunkSize: CHUNK_SIZE,
      fileName,
      fileSize: input.length,
      leafCount: leaves.length,
      leaves,
      root: bytesToHex(level[0]),
      createdAt: new Date().toISOString(),
    };
  }

  async function verifyFile(buffer, manifest) {
    if (!manifest || manifest.format !== VERSION || manifest.algorithm !== 'SHA-256' || manifest.fanout !== FANOUT || manifest.chunkSize !== CHUNK_SIZE) {
      throw new Error('Unsupported or invalid Sentinel Merkle manifest.');
    }
    if (!Array.isArray(manifest.leaves) || manifest.leaves.length < 1 || manifest.leaves.length > 100000) {
      throw new Error('Manifest has an invalid leaf list.');
    }
    if (buffer.byteLength !== manifest.fileSize) {
      return { valid: false, expectedRoot: manifest.root, actualRoot: null, reason: 'File size does not match the saved manifest.' };
    }
    const actual = await createManifest(buffer, manifest.fileName || 'file');
    const leavesMatch = actual.leaves.length === manifest.leaves.length && actual.leaves.every((leaf, index) => leaf === manifest.leaves[index]);
    const rootMatch = typeof manifest.root === 'string' && actual.root === manifest.root;
    return {
      valid: rootMatch && leavesMatch,
      expectedRoot: manifest.root,
      actualRoot: actual.root,
      reason: rootMatch && leavesMatch ? 'Merkle root and all chunk hashes match.' : 'File content differs from the saved Merkle manifest.',
    };
  }

  globalThis.SentinelMerkle = { createManifest, verifyFile, chunkSize: CHUNK_SIZE, fanout: FANOUT };
})();
