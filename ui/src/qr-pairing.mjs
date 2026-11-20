// Self-contained, offline ISO/IEC 18004 QR Code Byte-Mode Encoder & Pure SVG Renderer.
// Strict CSP compliant: zero external URLs, zero inline CSS attributes, zero DOM HTML injection,
// zero storage writes. Supports UTF-8 payloads up to 271 bytes (Versions 1..10, EC Levels M & L).

const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
));

// GF(256) log/antilog tables modulo primitive polynomial 0x11D (x^8 + x^4 + x^3 + x^2 + 1).
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function buildGeneratorPoly(degree) {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i += 1) {
    const next = new Uint8Array(poly.length + 1);
    const root = GF_EXP[i];
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], root);
    }
    poly = next;
  }
  return poly;
}

export function computeReedSolomonRemainder(dataBytes, ecDegree) {
  const gen = buildGeneratorPoly(ecDegree);
  const rem = new Uint8Array(ecDegree);
  for (let i = 0; i < dataBytes.length; i += 1) {
    const factor = dataBytes[i] ^ rem[0];
    rem.copyWithin(0, 1);
    rem[ecDegree - 1] = 0;
    if (factor !== 0) {
      for (let j = 0; j < ecDegree; j += 1) {
        rem[j] ^= gfMul(gen[j + 1], factor);
      }
    }
  }
  return rem;
}

// Alignment pattern center coordinates per ISO/IEC 18004 Annex E (Versions 1..10).
const ALIGNMENT_CENTERS = Object.freeze([
  [],
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
]);

// ISO/IEC 18004 Table 9 block specifications: [version, ecPerBlock, g1Blocks, g1DataCw, g2Blocks, g2DataCw].
const SPEC_TABLE_M = Object.freeze([
  [1, 10, 1, 16, 0, 0],
  [2, 16, 1, 28, 0, 0],
  [3, 26, 1, 44, 0, 0],
  [4, 18, 2, 32, 0, 0],
  [5, 24, 2, 43, 0, 0],
  [6, 16, 4, 27, 0, 0],
  [7, 18, 4, 31, 0, 0],
  [8, 22, 2, 38, 2, 39],
  [9, 22, 3, 36, 2, 37],
  [10, 26, 4, 43, 1, 44],
]);

const SPEC_TABLE_L = Object.freeze([
  [1, 7, 1, 19, 0, 0],
  [2, 10, 1, 34, 0, 0],
  [3, 15, 1, 55, 0, 0],
  [4, 20, 1, 80, 0, 0],
  [5, 26, 1, 108, 0, 0],
  [6, 18, 2, 68, 0, 0],
  [7, 20, 2, 78, 0, 0],
  [8, 24, 2, 97, 0, 0],
  [9, 30, 2, 116, 0, 0],
  [10, 18, 2, 68, 2, 69],
]);

const EC_FORMAT_BITS = Object.freeze({ L: 0b01, M: 0b00 });

function selectVersionSpec(byteLength, preferredEcLevel = 'M') {
  const order = preferredEcLevel === 'L' ? [['L', SPEC_TABLE_L], ['M', SPEC_TABLE_M]] : [['M', SPEC_TABLE_M], ['L', SPEC_TABLE_L]];
  for (const [ecLevel, table] of order) {
    for (const [version, ecPerBlock, g1Blocks, g1DataCw, g2Blocks, g2DataCw] of table) {
      const totalDataCw = g1Blocks * g1DataCw + g2Blocks * g2DataCw;
      const countBits = version <= 9 ? 8 : 16;
      const maxBytes = Math.floor((totalDataCw * 8 - 4 - countBits) / 8);
      if (byteLength <= maxBytes) {
        return { version, ecLevel, ecPerBlock, g1Blocks, g1DataCw, g2Blocks, g2DataCw, totalDataCw, countBits };
      }
    }
  }
  throw new Error('QR payload exceeds supported Version 10 byte capacity (271 bytes).');
}

function buildDataCodewords(utf8Bytes, spec) {
  const totalBitsCapacity = spec.totalDataCw * 8;
  const bits = [];
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i -= 1) {
      bits.push((val >>> i) & 1);
    }
  };
  // Mode indicator 0100 (Byte mode) + character count + payload bytes
  pushBits(0b0100, 4);
  pushBits(utf8Bytes.length, spec.countBits);
  for (let i = 0; i < utf8Bytes.length; i += 1) {
    pushBits(utf8Bytes[i], 8);
  }
  const terminatorLen = Math.min(4, totalBitsCapacity - bits.length);
  for (let i = 0; i < terminatorLen; i += 1) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);

  const codewords = new Uint8Array(spec.totalDataCw);
  const filledBytes = bits.length / 8;
  for (let i = 0; i < filledBytes; i += 1) {
    let b = 0;
    for (let bit = 0; bit < 8; bit += 1) {
      b = (b << 1) | bits[i * 8 + bit];
    }
    codewords[i] = b;
  }
  const padBytes = [0xec, 0x11];
  for (let i = filledBytes; i < spec.totalDataCw; i += 1) {
    codewords[i] = padBytes[(i - filledBytes) & 1];
  }
  return codewords;
}

function buildInterleavedCodewords(dataCodewords, spec) {
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (let b = 0; b < spec.g1Blocks; b += 1) {
    const slice = dataCodewords.subarray(offset, offset + spec.g1DataCw);
    offset += spec.g1DataCw;
    dataBlocks.push(slice);
    ecBlocks.push(computeReedSolomonRemainder(slice, spec.ecPerBlock));
  }
  for (let b = 0; b < spec.g2Blocks; b += 1) {
    const slice = dataCodewords.subarray(offset, offset + spec.g2DataCw);
    offset += spec.g2DataCw;
    dataBlocks.push(slice);
    ecBlocks.push(computeReedSolomonRemainder(slice, spec.ecPerBlock));
  }

  const out = [];
  const maxDataLen = Math.max(spec.g1DataCw, spec.g2DataCw);
  for (let i = 0; i < maxDataLen; i += 1) {
    for (let b = 0; b < dataBlocks.length; b += 1) {
      if (i < dataBlocks[b].length) out.push(dataBlocks[b][i]);
    }
  }
  for (let i = 0; i < spec.ecPerBlock; i += 1) {
    for (let b = 0; b < ecBlocks.length; b += 1) {
      out.push(ecBlocks[b][i]);
    }
  }
  return new Uint8Array(out);
}

export function computeFormatBits(ecLevel, maskPattern) {
  const data5 = ((EC_FORMAT_BITS[ecLevel] ?? 0) << 3) | (maskPattern & 0x07);
  let rem = data5 << 10;
  for (let bit = 14; bit >= 10; bit -= 1) {
    if ((rem >>> bit) & 1) {
      rem ^= 0x537 << (bit - 10);
    }
  }
  return (((data5 << 10) | rem) ^ 0x5412) & 0x7fff;
}

export function computeVersionBits(version) {
  let rem = version << 12;
  for (let bit = 17; bit >= 12; bit -= 1) {
    if ((rem >>> bit) & 1) {
      rem ^= 0x1f25 << (bit - 12);
    }
  }
  return ((version << 12) | rem) & 0x3ffff;
}

function placeFunctionPatterns(size, version) {
  const modules = Array.from({ length: size }, () => new Uint8Array(size));
  const isFunc = Array.from({ length: size }, () => new Uint8Array(size));
  const setFunc = (r, c, dark) => {
    if (r < 0 || r >= size || c < 0 || c >= size) return;
    modules[r][c] = dark ? 1 : 0;
    isFunc[r][c] = 1;
  };

  // 3 Finder patterns + 1-module white separators
  const drawFinder = (topR, leftC) => {
    for (let dr = -1; dr <= 7; dr += 1) {
      for (let dc = -1; dc <= 7; dc += 1) {
        const rr = topR + dr;
        const cc = leftC + dc;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        const inOuter = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
        const onRing = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const inCore = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        setFunc(rr, cc, inOuter && (onRing || inCore));
      }
    }
  };
  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  // Timing patterns along row 6 and col 6
  for (let i = 8; i < size - 8; i += 1) {
    const dark = i % 2 === 0;
    setFunc(6, i, dark);
    setFunc(i, 6, dark);
  }

  // Alignment patterns (excluding the 3 finder corners)
  const centers = ALIGNMENT_CENTERS[version] ?? [];
  const lastIdx = centers.length - 1;
  for (let i = 0; i < centers.length; i += 1) {
    for (let j = 0; j < centers.length; j += 1) {
      if ((i === 0 && j === 0) || (i === 0 && j === lastIdx) || (i === lastIdx && j === 0)) continue;
      const cr = centers[i];
      const cc = centers[j];
      for (let dr = -2; dr <= 2; dr += 1) {
        for (let dc = -2; dc <= 2; dc += 1) {
          const dist = Math.max(Math.abs(dr), Math.abs(dc));
          setFunc(cr + dr, cc + dc, dist !== 1);
        }
      }
    }
  }

  // Reserve format info strips + dark module at (size - 8, 8)
  for (let i = 0; i <= 8; i += 1) {
    if (i !== 6) {
      setFunc(8, i, false);
      setFunc(i, 8, false);
    }
  }
  for (let i = 0; i < 8; i += 1) {
    setFunc(8, size - 1 - i, false);
    if (i < 7) setFunc(size - 1 - i, 8, false);
  }
  setFunc(size - 8, 8, true);

  // Version info blocks for Version >= 7
  if (version >= 7) {
    const vBits = computeVersionBits(version);
    for (let i = 0; i < 18; i += 1) {
      const bit = Boolean((vBits >>> i) & 1);
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setFunc(a, b, bit);
      setFunc(b, a, bit);
    }
  }

  return { modules, isFunc };
}

function writeFormatBits(modules, size, ecLevel, maskPattern) {
  const fBits = computeFormatBits(ecLevel, maskPattern);
  // Copy 1 around top-left finder
  const copy1Coords = [
    [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
    [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8],
  ];
  for (let idx = 0; idx < 15; idx += 1) {
    const bit = (fBits >>> (14 - idx)) & 1;
    const [r, c] = copy1Coords[idx];
    modules[r][c] = bit;
  }
  // Copy 2 along bottom-left & top-right
  for (let idx = 0; idx < 7; idx += 1) {
    modules[size - 1 - idx][8] = (fBits >>> (14 - idx)) & 1;
  }
  for (let idx = 0; idx < 8; idx += 1) {
    modules[8][size - 8 + idx] = (fBits >>> (7 - idx)) & 1;
  }
}

export function maskCondition(maskPattern, r, c) {
  switch (maskPattern) {
    case 0: return (r + c) % 2 === 0;
    case 1: return r % 2 === 0;
    case 2: return c % 3 === 0;
    case 3: return (r + c) % 3 === 0;
    case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6: return ((((r * c) % 2) + ((r * c) % 3)) % 2) === 0;
    case 7: return ((((r + c) % 2) + ((r * c) % 3)) % 2) === 0;
    default: return false;
  }
}

function computePenaltyScore(modules, size) {
  let penalty = 0;
  // N1: 5+ consecutive same-color modules in rows and cols
  const scoreLineRuns = (getCell) => {
    for (let outer = 0; outer < size; outer += 1) {
      let runVal = getCell(outer, 0);
      let runLen = 1;
      for (let inner = 1; inner < size; inner += 1) {
        const v = getCell(outer, inner);
        if (v === runVal) {
          runLen += 1;
        } else {
          if (runLen >= 5) penalty += 3 + (runLen - 5);
          runVal = v;
          runLen = 1;
        }
      }
      if (runLen >= 5) penalty += 3 + (runLen - 5);
    }
  };
  scoreLineRuns((r, c) => modules[r][c]);
  scoreLineRuns((c, r) => modules[r][c]);

  // N2: 2x2 same-color blocks
  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const v = modules[r][c];
      if (v === modules[r][c + 1] && v === modules[r + 1][c] && v === modules[r + 1][c + 1]) {
        penalty += 3;
      }
    }
  }

  // N3: Finder-like 1:1:3:1:1 patterns preceded or followed by 4 light modules
  const matchFinderLike = (getCell) => {
    for (let outer = 0; outer < size; outer += 1) {
      for (let idx = 0; idx <= size - 11; idx += 1) {
        // 10111010000 or 00001011101
        const p1 = getCell(outer, idx) === 1
          && getCell(outer, idx + 1) === 0
          && getCell(outer, idx + 2) === 1
          && getCell(outer, idx + 3) === 1
          && getCell(outer, idx + 4) === 1
          && getCell(outer, idx + 5) === 0
          && getCell(outer, idx + 6) === 1
          && getCell(outer, idx + 7) === 0
          && getCell(outer, idx + 8) === 0
          && getCell(outer, idx + 9) === 0
          && getCell(outer, idx + 10) === 0;
        const p2 = getCell(outer, idx) === 0
          && getCell(outer, idx + 1) === 0
          && getCell(outer, idx + 2) === 0
          && getCell(outer, idx + 3) === 0
          && getCell(outer, idx + 4) === 1
          && getCell(outer, idx + 5) === 0
          && getCell(outer, idx + 6) === 1
          && getCell(outer, idx + 7) === 1
          && getCell(outer, idx + 8) === 1
          && getCell(outer, idx + 9) === 0
          && getCell(outer, idx + 10) === 1;
        if (p1 || p2) penalty += 40;
      }
    }
  };
  matchFinderLike((r, c) => modules[r][c]);
  matchFinderLike((c, r) => modules[r][c]);

  // N4: Dark module ratio balance
  let darkCount = 0;
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      if (modules[r][c] === 1) darkCount += 1;
    }
  }
  const total = size * size;
  const fivePctSteps = Math.floor(Math.abs(darkCount * 20 - total * 10) / total);
  penalty += fivePctSteps * 10;
  return penalty;
}

/** Encode a UTF-8 string into an ISO/IEC 18004 QR Code matrix. */
export function encodeQrMatrix(text, preferredEcLevel = 'M') {
  if (typeof text !== 'string' || text.length === 0) {
    throw new Error('QR payload must be a non-empty string.');
  }
  const utf8Bytes = new TextEncoder().encode(text);
  const spec = selectVersionSpec(utf8Bytes.length, preferredEcLevel);
  const size = 17 + spec.version * 4;
  const dataCodewords = buildDataCodewords(utf8Bytes, spec);
  const interleaved = buildInterleavedCodewords(dataCodewords, spec);

  const base = placeFunctionPatterns(size, spec.version);

  // Place interleaved data + EC bits in upward/downward 2-column zig-zag
  let bitIdx = 0;
  const totalBits = interleaved.length * 8;
  let upward = true;
  for (let rightCol = size - 1; rightCol >= 1; rightCol -= 2) {
    if (rightCol === 6) rightCol = 5;
    for (let step = 0; step < size; step += 1) {
      const r = upward ? (size - 1 - step) : step;
      for (let dc = 0; dc <= 1; dc += 1) {
        const c = rightCol - dc;
        if (base.isFunc[r][c]) continue;
        let bit = 0;
        if (bitIdx < totalBits) {
          bit = (interleaved[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1;
          bitIdx += 1;
        }
        base.modules[r][c] = bit;
      }
    }
    upward = !upward;
  }

  // Evaluate all 8 ISO masks and pick the lowest penalty score
  let bestMask = 0;
  let bestPenalty = Number.POSITIVE_INFINITY;
  let bestModules = null;

  for (let mask = 0; mask < 8; mask += 1) {
    const candidate = base.modules.map((row) => new Uint8Array(row));
    for (let r = 0; r < size; r += 1) {
      for (let c = 0; c < size; c += 1) {
        if (!base.isFunc[r][c] && maskCondition(mask, r, c)) {
          candidate[r][c] ^= 1;
        }
      }
    }
    writeFormatBits(candidate, size, spec.ecLevel, mask);
    const score = computePenaltyScore(candidate, size);
    if (score < bestPenalty) {
      bestPenalty = score;
      bestMask = mask;
      bestModules = candidate;
    }
  }

  return Object.freeze({
    version: spec.version,
    ecLevel: spec.ecLevel,
    mask: bestMask,
    size,
    spec: Object.freeze({ ...spec }),
    isFunction: Object.freeze(base.isFunc.map((r) => Object.freeze([...r]))),
    modules: Object.freeze(bestModules.map((r) => Object.freeze([...r]))),
  });
}

/** Render a scannable pure-SVG QR Code with 4-module quiet zone and zero inline CSS attributes. */
export function renderQrSvg(text, { margin = 4, ecLevel = 'M', ariaLabel = 'Device pairing QR code' } = {}) {
  const qr = encodeQrMatrix(text, ecLevel);
  const pad = Math.max(4, Number.isSafeInteger(margin) ? margin : 4);
  const viewSize = qr.size + pad * 2;
  const paths = [];
  for (let r = 0; r < qr.size; r += 1) {
    const row = qr.modules[r];
    let c = 0;
    while (c < qr.size) {
      if (row[c] === 1) {
        let run = 1;
        while (c + run < qr.size && row[c + run] === 1) run += 1;
        paths.push(`M${c + pad} ${r + pad}h${run}v1h-${run}z`);
        c += run;
      } else {
        c += 1;
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewSize} ${viewSize}" width="220" height="220" class="qr-pairing-svg" shape-rendering="crispEdges" role="img" aria-label="${esc(ariaLabel)}"><rect width="${viewSize}" height="${viewSize}" fill="#ffffff"/><path fill="#000000" d="${paths.join('')}"/></svg>`;
}

export const SESSION_SCOPES = Object.freeze({
  OWNER_FULL_CONTROL: 'OWNER_FULL_CONTROL',
  DEVICE_READ_AND_EXPLAINER: 'DEVICE_READ_AND_EXPLAINER',
});

export const PAIRING_DEFAULT_TTL_SECONDS = 120;

/** Return true only when the live cockpit session holds full owner control authority. */
export function isOwnerControlSession(state) {
  if (!state?.liveStreamConnected) return false;
  if (state?.sessionScope === SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER) return false;
  if (state?.ownerControlsAllowed === false) return false;
  return true;
}

/** Build a validated same-origin single-use pairing URL (?pair_code=...) without ever embedding a bearer token. */
export function buildPairingUrl(origin, pairCode) {
  if (typeof pairCode !== 'string') {
    throw new Error('Valid single-use pairing code required to generate pairing QR.');
  }
  const trimmed = pairCode.trim();
  if (trimmed.length < 16 || /[\r\n\0\s]/.test(trimmed) || /(?:^|[?&])token=/i.test(trimmed)) {
    throw new Error('Valid single-use pairing code required to generate pairing QR.');
  }
  const parsedOrigin = new URL(String(origin));
  if (!['http:', 'https:'].includes(parsedOrigin.protocol)) {
    throw new Error('Pairing QR requires HTTP or HTTPS origin.');
  }
  return `${parsedOrigin.origin}/ui/index.html?pair_code=${encodeURIComponent(trimmed)}`;
}

/**
 * Strip ?pair_code= and any legacy ?token= from browser URL immediately on boot before network I/O.
 * Never accepts or returns ?token= as an authentication credential.
 */
export function extractAndStripBootPairingParams(locationObj, historyObj = null) {
  if (!locationObj || typeof locationObj.search !== 'string') {
    return Object.freeze({ pairCode: null, strippedLegacyToken: false, cleanPath: '' });
  }
  const params = new URLSearchParams(locationObj.search);
  const hadLegacyToken = params.has('token');
  const hadPairCode = params.has('pair_code');
  const rawPairCode = params.get('pair_code');
  let cleanPath = `${locationObj.pathname ?? '/'}${locationObj.search ?? ''}${locationObj.hash ?? ''}`;
  if (hadLegacyToken || hadPairCode) {
    params.delete('token');
    params.delete('pair_code');
    const qs = params.toString();
    cleanPath = `${locationObj.pathname ?? '/'}${qs ? `?${qs}` : ''}${locationObj.hash ?? ''}`;
    try { historyObj?.replaceState?.(null, '', cleanPath); } catch { /* Optional history API */ }
  }
  let validPairCode = null;
  if (typeof rawPairCode === 'string') {
    const trimmed = rawPairCode.trim();
    if (trimmed.length >= 16 && !/[\r\n\0\s]/.test(trimmed)) {
      validPairCode = trimmed;
    }
  }
  return Object.freeze({
    pairCode: validPairCode,
    strippedLegacyToken: Boolean(hadLegacyToken),
    cleanPath,
  });
}

/** Validate POST /api/pair-code response and guarantee primary bearer is never echoed as pair_code. */
export function normalizePairCodeMintResponse(doc, primaryOwnerBearer = null) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('Invalid pair-code response payload.');
  }
  const code = typeof doc.pair_code === 'string' ? doc.pair_code.trim() : '';
  if (code.length < 16 || /[\r\n\0\s]/.test(code)) {
    throw new Error('Server returned an invalid single-use pairing code.');
  }
  if (typeof primaryOwnerBearer === 'string' && primaryOwnerBearer.trim().length > 0 && code === primaryOwnerBearer.trim()) {
    throw new Error('Refusing pairing code that matches primary owner bearer.');
  }
  const rawTtl = Number.isSafeInteger(doc.ttl_seconds) ? doc.ttl_seconds : PAIRING_DEFAULT_TTL_SECONDS;
  const ttlSeconds = Math.max(5, Math.min(300, rawTtl));
  const expiresAt = typeof doc.expires_at === 'string' && doc.expires_at.length <= 64 ? doc.expires_at : null;
  const scope = doc.scope === SESSION_SCOPES.OWNER_FULL_CONTROL
    ? SESSION_SCOPES.OWNER_FULL_CONTROL
    : SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER;
  return Object.freeze({ pairCode: code, expiresAt, ttlSeconds, scope });
}

/** Validate POST /api/pair-exchange response returning a least-privilege device bearer. */
export function normalizePairExchangeResponse(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('Invalid pair-exchange response payload.');
  }
  const sessionToken = typeof doc.session_token === 'string' ? doc.session_token.trim() : '';
  if (sessionToken.length < 16 || /[\r\n\0]/.test(sessionToken)) {
    throw new Error('Server returned an invalid paired device session credential.');
  }
  const sessionScope = doc.session_scope === SESSION_SCOPES.OWNER_FULL_CONTROL
    ? SESSION_SCOPES.OWNER_FULL_CONTROL
    : SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER;
  const ownerControlsAllowed = Boolean(
    doc.owner_controls_allowed === true && sessionScope === SESSION_SCOPES.OWNER_FULL_CONTROL,
  );
  const sessionEpoch = typeof doc.session_epoch === 'string' && doc.session_epoch.length <= 64 ? doc.session_epoch : null;
  const expiresAt = typeof doc.expires_at === 'string' && doc.expires_at.length <= 64 ? doc.expires_at : null;
  return Object.freeze({
    sessionToken,
    sessionScope,
    ownerControlsAllowed,
    sessionEpoch,
    expiresAt,
  });
}

/** Validate GET /api/auth-session readback for authoritative session privilege display. */
export function normalizeAuthSessionResponse(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) || doc.authenticated !== true) {
    return null;
  }
  const sessionScope = doc.session_scope === SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER
    ? SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER
    : SESSION_SCOPES.OWNER_FULL_CONTROL;
  const ownerControlsAllowed = sessionScope === SESSION_SCOPES.OWNER_FULL_CONTROL
    && doc.owner_controls_allowed !== false;
  const expiresAt = typeof doc.expires_at === 'string' && doc.expires_at.length <= 64 ? doc.expires_at : null;
  return Object.freeze({
    authenticated: true,
    sessionScope,
    ownerControlsAllowed,
    expiresAt,
  });
}

export function renderQrPairingDrawer(qrSvgMarkup, copiedNotice = null, options = null) {
  if (typeof qrSvgMarkup !== 'string' || !qrSvgMarkup.startsWith('<svg ')) return '';
  const ttlSeconds = Number.isSafeInteger(options?.ttlSeconds) ? options.ttlSeconds : PAIRING_DEFAULT_TTL_SECONDS;
  const expiresAt = typeof options?.expiresAt === 'string' && options.expiresAt.trim() ? options.expiresAt.trim() : null;
  const scopeLabel = typeof options?.scopeLabel === 'string' && options.scopeLabel.trim()
    ? options.scopeLabel.trim()
    : SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER;
  const expiryDetail = expiresAt ? `${ttlSeconds}s single-use TTL · Expires ${esc(expiresAt)}` : `${ttlSeconds}s single-use server TTL`;
  return `<section class="panel qr-pairing-drawer" data-qr-pairing-panel="true" aria-label="Single-Use Phone and Tablet QR Pairing">
    <div class="section-heading">
      <div>
        <p class="eyebrow">SINGLE-USE PAIRING NONCE · ${expiryDetail} · ZERO PRIMARY BEARER IN URL</p>
        <h2>Pair Phone or Android Tablet (Least-Privilege Read &amp; Explainer Session)</h2>
      </div>
      <div class="qr-pairing-actions">
        <button type="button" class="button button-small button-secondary" data-copy-unlock-link="true">Copy Single-Use Pairing Link</button>
        <button type="button" class="button button-small button-warning" data-revoke-qr-pairing="true">Revoke Pairing Code</button>
        <button type="button" class="button button-small button-primary" data-toggle-qr-pairing="true">Hide QR</button>
      </div>
    </div>
    <div class="qr-pairing-body">
      <div class="qr-pairing-frame">${qrSvgMarkup}</div>
      <div class="qr-pairing-instructions">
        <p><strong>Least-Privilege Read &amp; Explainer Session (<code>${esc(scopeLabel)}</code>):</strong></p>
        <ol class="qr-pairing-steps">
          <li>Open the Camera app on your Android tablet or iPhone and scan this single-use QR square within <strong>${esc(ttlSeconds)} seconds</strong>.</li>
          <li>Your tablet strips <code>?pair_code=</code> immediately from browser history and exchanges the one-time nonce via <code>POST /api/pair-exchange</code> — your Primary Owner Key is never placed in URLs, QR codes, or server query logs.</li>
          <li>Paired devices can view live 3-Broker Equity, Realized P&amp;L Provenance, and Gemini 4 Neon Voice Explainer while <strong>owner trading, model, risk-gear, and treasury controls stay locked</strong>. Click <strong>Revoke Pairing Code</strong> anytime to invalidate unused codes and active paired device sessions on the server.</li>
        </ol>
        ${copiedNotice ? `<p class="quiet-note" role="status">${esc(copiedNotice)}</p>` : ''}
      </div>
    </div>
  </section>`;
}
