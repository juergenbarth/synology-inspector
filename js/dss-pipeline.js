/**
 * dss-pipeline.js
 *
 * Parses a Synology .dss configuration backup file and returns the structured
 * data needed by the compliance checks.
 *
 * .dss format:
 *   XZ-compressed TAR archive
 *   └── ConfigBkp/
 *       ├── _Syno_ConfBkp.db          — SQLite key-value store (main config)
 *       ├── config_info                — plain text: OS version, model
 *       └── tls_profile/
 *           └── datastore.json         — TLS level per service
 *
 * Dependencies (must be loaded before this file):
 *   xz-decompress.js  → window['xz-decompress'].XzReadableStream
 *   tar-parser.js     → parseTar()
 *   sqlite-reader.js  → buildSynoConfigMap()
 *
 * Returns a Promise<ParseResult> where ParseResult is:
 * {
 *   config:     Map<string, string>   key-value pairs from SQLite
 *   tlsProfile: Object | null         parsed tls_profile/datastore.json
 *   info:       Object                DSM version, model, etc.
 *   fileName:   string
 *   fileSize:   number
 * }
 */

/**
 * Parse the config_info plain-text file.
 * Format: key="value"\n per line (shell variable syntax).
 *
 * @param {Uint8Array} data
 * @returns {Object}
 */
function parseConfigInfo(data) {
    const text   = new TextDecoder('utf-8', { fatal: false }).decode(data);
    const result = {};
    for (const line of text.split('\n')) {
        const m = line.match(/^(\w+)="([^"]*)"/);
        if (m) result[m[1]] = m[2];
    }
    return result;
}

/**
 * Decompress an XZ-compressed Uint8Array using XzReadableStream (xz-decompress).
 *
 * @param {Uint8Array} compressed
 * @returns {Promise<Uint8Array>}
 */
async function decompressXZ(compressed) {
    const XzReadableStream = window['xz-decompress']?.XzReadableStream;
    if (!XzReadableStream) {
        throw new Error('xz-decompress not loaded');
    }

    const inputStream = new ReadableStream({
        start(controller) {
            controller.enqueue(compressed);
            controller.close();
        }
    });

    const xzStream = new XzReadableStream(inputStream);
    const reader   = xzStream.getReader();
    const chunks   = [];

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
    }

    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const result   = new Uint8Array(totalLen);
    let offset     = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return result;
}

/**
 * Main entry point.  Reads a File (or Blob) and resolves with a ParseResult.
 *
 * @param {File} file
 * @returns {Promise<ParseResult>}
 */
function parseDSSFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onerror = () => reject(new Error(t('errFileRead')));

        reader.onload = async (event) => {
            const rawBytes = new Uint8Array(event.target.result);

            let tarBytes;
            try {
                // Step 1: XZ decompression
                tarBytes = await decompressXZ(rawBytes);
            } catch (err) {
                return reject(new Error(t('errDecompress') + ': ' + err.message));
            }

            try {
                // Step 2: TAR parsing
                const tarEntries = parseTar(tarBytes);

                // Step 3: locate required files
                const dbEntry      = tarEntries.find(e => e.name.endsWith('_Syno_ConfBkp.db'));
                const infoEntry    = tarEntries.find(e => e.name.endsWith('config_info'));
                const tlsJsonEntry = tarEntries.find(e => e.name.endsWith('tls_profile/datastore.json'));

                if (!dbEntry) {
                    return reject(new Error(t('errNoDb')));
                }

                // Step 4: parse SQLite config
                const config = buildSynoConfigMap(dbEntry.data);

                // Step 5: parse config_info
                const info = infoEntry ? parseConfigInfo(infoEntry.data) : {};

                // Step 6: parse TLS profile
                let tlsProfile = null;
                if (tlsJsonEntry) {
                    try {
                        const json = new TextDecoder('utf-8').decode(tlsJsonEntry.data);
                        tlsProfile = JSON.parse(json);
                    } catch (_) { /* not critical */ }
                }

                resolve({
                    config,
                    tlsProfile,
                    info,
                    fileName: file.name,
                    fileSize: file.size,
                });
            } catch (err) {
                reject(new Error(t('errParse') + ': ' + err.message));
            }
        };

        reader.readAsArrayBuffer(file);
    });
}
