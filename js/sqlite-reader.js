/**
 * sqlite-reader.js
 *
 * Minimal SQLite 3 database reader.
 * Performs a full table scan of a single named table and returns all rows
 * as arrays of column values.
 *
 * Supported page types: leaf table (0x0D), interior table (0x05).
 * Overflow pages are NOT followed — values larger than the inline threshold
 * will be truncated. All security-relevant keys in the Synology .dss backup
 * fit within the inline payload, so this is safe for our use case.
 *
 * SQLite 3 format reference: https://www.sqlite.org/fileformat.html
 */

// ── Low-level helpers ─────────────────────────────────────────────────────────

function sqliteReadU16(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function sqliteReadU32(bytes, offset) {
    return (((bytes[offset] << 24) | (bytes[offset + 1] << 16) |
              (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0);
}

/**
 * Read a SQLite varint (big-endian, 1–9 bytes, 7 bits per byte).
 * Returns { value, length }.
 */
function sqliteReadVarint(bytes, offset) {
    let value = 0;
    let length = 0;
    for (let i = 0; i < 9; i++) {
        const b = bytes[offset + i];
        length++;
        if (i < 8) {
            value = value * 128 + (b & 0x7f);
            if (!(b & 0x80)) break;
        } else {
            value = value * 256 + b; // 9th byte: all 8 bits
        }
    }
    return { value, length };
}

// ── Record decoder ────────────────────────────────────────────────────────────

/**
 * Decode a SQLite record payload into an array of column values.
 * Text columns → string, integer columns → number, NULL → null, blob → Uint8Array.
 */
function sqliteDecodeRecord(payload) {
    const decoder = new TextDecoder('utf-8', { fatal: false });
    let pos = 0;

    // Header: total header length varint, then one varint per column (serial type)
    const hdrSizeV = sqliteReadVarint(payload, pos);
    const headerSize = hdrSizeV.value;
    pos += hdrSizeV.length;

    const serialTypes = [];
    while (pos < headerSize) {
        const stV = sqliteReadVarint(payload, pos);
        serialTypes.push(stV.value);
        pos += stV.length;
    }

    pos = headerSize; // data section starts here
    const values = [];

    for (const st of serialTypes) {
        if (pos > payload.length) { values.push(null); continue; }

        if (st === 0) {
            values.push(null);
        } else if (st === 1) {
            values.push(payload[pos]); pos += 1;
        } else if (st === 2) {
            values.push((payload[pos] << 8) | payload[pos + 1]); pos += 2;
        } else if (st === 3) {
            values.push((payload[pos] << 16) | (payload[pos + 1] << 8) | payload[pos + 2]); pos += 3;
        } else if (st === 4) {
            values.push(sqliteReadU32(payload, pos)); pos += 4;
        } else if (st === 5) {
            let v = 0;
            for (let i = 0; i < 6; i++) v = v * 256 + payload[pos + i];
            values.push(v); pos += 6;
        } else if (st === 6 || st === 7) {
            values.push(null); pos += 8; // 8-byte int / float — not needed
        } else if (st === 8) {
            values.push(0);
        } else if (st === 9) {
            values.push(1);
        } else if (st >= 12 && st % 2 === 0) {
            const len = (st - 12) / 2;
            values.push(payload.slice(pos, pos + len)); pos += len;
        } else if (st >= 13 && st % 2 === 1) {
            const len = (st - 13) / 2;
            const available = Math.min(len, payload.length - pos);
            values.push(decoder.decode(payload.slice(pos, pos + available)));
            pos += available;
        } else {
            values.push(null);
        }
    }

    return values;
}

// ── B-tree traversal ──────────────────────────────────────────────────────────

/**
 * Recursively scan all leaf pages of a table B-tree.
 * Returns an array of decoded rows (each row is an array of column values).
 *
 * @param {Uint8Array} bytes      Full database bytes
 * @param {number}     pageNum    1-based page number to scan
 * @param {number}     pageSize   Database page size in bytes
 * @returns {Array[]}
 */
function sqliteScanBTree(bytes, pageNum, pageSize) {
    const results = [];
    const pageOffset = (pageNum - 1) * pageSize;
    const isPage1   = (pageNum === 1);
    const hdrOffset = isPage1 ? pageOffset + 100 : pageOffset; // page 1 has 100-byte DB header

    const pageType = bytes[hdrOffset];
    const numCells = sqliteReadU16(bytes, hdrOffset + 3);

    if (pageType === 0x0D) {
        // ── Leaf table page ────────────────────────────────────────────────
        // 8-byte page header; cell pointer array starts immediately after
        const cellPtrBase = hdrOffset + 8;

        for (let i = 0; i < numCells; i++) {
            const cellPtr    = sqliteReadU16(bytes, cellPtrBase + i * 2);
            let   cellOffset = pageOffset + cellPtr;

            // Varint: total payload length
            const payloadLenV = sqliteReadVarint(bytes, cellOffset);
            cellOffset += payloadLenV.length;

            // Varint: integer row key
            const rowIdV = sqliteReadVarint(bytes, cellOffset);
            cellOffset += rowIdV.length;

            // Inline payload (may be truncated if cell has overflow pages)
            const inlineLen = Math.min(payloadLenV.value, bytes.length - cellOffset);
            const payload   = bytes.slice(cellOffset, cellOffset + inlineLen);

            try {
                results.push(sqliteDecodeRecord(payload));
            } catch (_) {
                // Skip malformed records rather than aborting the scan
            }
        }
    } else if (pageType === 0x05) {
        // ── Interior table page ────────────────────────────────────────────
        // 12-byte page header (8 + 4-byte rightmost child page number)
        const rightChildPage = sqliteReadU32(bytes, hdrOffset + 8);
        const cellPtrBase    = hdrOffset + 12;

        for (let i = 0; i < numCells; i++) {
            const cellPtr   = sqliteReadU16(bytes, cellPtrBase + i * 2);
            const cellOffset = pageOffset + cellPtr;
            // Cell: 4-byte left child page number + varint key (key not needed)
            const childPage = sqliteReadU32(bytes, cellOffset);
            results.push(...sqliteScanBTree(bytes, childPage, pageSize));
        }

        // Process the rightmost child
        results.push(...sqliteScanBTree(bytes, rightChildPage, pageSize));
    }

    return results;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Read all rows from a named table in a SQLite 3 database.
 *
 * @param {ArrayBuffer|Uint8Array} buffer  Raw SQLite 3 database bytes
 * @param {string}                 tableName
 * @returns {Array[]}  Array of rows; each row is an array of column values
 * @throws  {Error}    If the buffer is not a valid SQLite 3 database
 */
function readSQLiteTable(buffer, tableName) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

    // Validate SQLite 3 magic string (first 16 bytes)
    const magic = new TextDecoder('ascii', { fatal: false }).decode(bytes.slice(0, 15));
    if (magic !== 'SQLite format 3') {
        throw new Error('Not a SQLite 3 database');
    }

    // Page size (bytes 16–17, big-endian); value 1 means 65536
    let pageSize = sqliteReadU16(bytes, 16);
    if (pageSize === 1) pageSize = 65536;

    // sqlite_master is always at page 1.
    // Schema: type TEXT, name TEXT, tbl_name TEXT, rootpage INTEGER, sql TEXT
    const masterRows = sqliteScanBTree(bytes, 1, pageSize);

    let rootPage = null;
    for (const row of masterRows) {
        if (row[0] === 'table' && row[1] === tableName) {
            rootPage = Number(row[3]);
            break;
        }
    }

    if (!rootPage) return [];

    return sqliteScanBTree(bytes, rootPage, pageSize);
}

/**
 * Build a Map from a confbkp_config_tb-style table (key TEXT, value TEXT).
 *
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {Map<string, string>}
 */
function buildSynoConfigMap(buffer) {
    const rows = readSQLiteTable(buffer, 'confbkp_config_tb');
    const map  = new Map();
    for (const row of rows) {
        if (typeof row[0] === 'string' && row[0].length > 0) {
            map.set(row[0], typeof row[1] === 'string' ? row[1] : null);
        }
    }
    return map;
}
