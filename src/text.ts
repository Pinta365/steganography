/**
 * Linguistic & Text Steganography Module
 *
 * Hides secret data in plain text using Zero-Width Characters (ZWC).
 * Pipeline: Compress → Encrypt (AES-256-CTR) → Base-6 ZWC encoding
 */

const ZWC_MAP = [
    "\u200b",
    "\u200c",
    "\u200d",
    "\ufeff",
    "\u2060",
    "\u2061",
] as const;

const START_SENTINEL = "\u200b\u200c\u200b";
const END_SENTINEL = "\u200c\u200b\u200c";

const PAYLOAD_TYPE_TEXT = 0x01;
const PAYLOAD_TYPE_BINARY = 0x02;

const ZWC_PATTERN = /[\u200b\u200c\u200d\ufeff\u2060\u2061]+/g;

/**
 * Branded type for steganographic text containing hidden ZWC data
 * This helps distinguish stega text from regular strings for type safety
 */
export type StegaText = string & { readonly __brand: "StegaText" };

/**
 * Creates a StegaText value from a string
 * Internal helper to brand strings as stega text
 */
function asStegaText(text: string): StegaText {
    return text as StegaText;
}

/**
 * Compresses data using the native Web CompressionStream API (deflate)
 */
async function compress(data: Uint8Array): Promise<Uint8Array> {
    const cs = new CompressionStream("deflate");
    const writer = cs.writable.getWriter();
    const buffer = new Uint8Array(data);
    writer.write(buffer);
    writer.close();

    const chunks: Uint8Array[] = [];
    const reader = cs.readable.getReader();

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
    }

    const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }

    return result;
}

/**
 * Decompresses data using the native Web DecompressionStream API (deflate)
 */
async function decompress(data: Uint8Array): Promise<Uint8Array> {
    const ds = new DecompressionStream("deflate");
    const writer = ds.writable.getWriter();
    const buffer = new Uint8Array(data);
    writer.write(buffer);
    writer.close();

    const chunks: Uint8Array[] = [];
    const reader = ds.readable.getReader();

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
    }

    const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }

    return result;
}

/**
 * Check if Web Crypto API is available
 */
function checkCryptoAvailable(): void {
    if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
        throw new Error(
            "Web Crypto API not available. Encryption requires HTTPS or localhost. " +
                "Please access this page via https:// or http://localhost/",
        );
    }
}

/**
 * Derives an AES-256 key from a password using PBKDF2
 */
async function deriveKey(
    password: string,
    salt: Uint8Array,
): Promise<CryptoKey> {
    checkCryptoAvailable();

    const encoder = new TextEncoder();
    const keyMaterial = await globalThis.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"],
    );

    return globalThis.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: new Uint8Array(salt),
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-CTR", length: 256 },
        false,
        ["encrypt", "decrypt"],
    );
}

/**
 * Encrypts data using AES-256-CTR
 * Returns: [16-byte salt][16-byte counter][encrypted data]
 */
async function encrypt(
    data: Uint8Array,
    password: string,
): Promise<Uint8Array> {
    checkCryptoAvailable();

    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const counter = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);

    const encrypted = await globalThis.crypto.subtle.encrypt(
        { name: "AES-CTR", counter, length: 64 },
        key,
        new Uint8Array(data),
    );

    const result = new Uint8Array(32 + encrypted.byteLength);
    result.set(salt, 0);
    result.set(counter, 16);
    result.set(new Uint8Array(encrypted), 32);

    return result;
}

/**
 * Decrypts data using AES-256-CTR
 * Expects: [16-byte salt][16-byte counter][encrypted data]
 */
async function decrypt(
    data: Uint8Array,
    password: string,
): Promise<Uint8Array> {
    checkCryptoAvailable();

    if (data.length < 33) {
        throw new Error("Encrypted data too short");
    }

    const salt = data.slice(0, 16);
    const counter = data.slice(16, 32);
    const ciphertext = data.slice(32);

    const key = await deriveKey(password, salt);

    const decrypted = await globalThis.crypto.subtle.decrypt(
        { name: "AES-CTR", counter, length: 64 },
        key,
        ciphertext,
    );

    return new Uint8Array(decrypted);
}

/**
 * Converts bytes to Base-6 ZWC string
 */
function bytesToZWC(bytes: Uint8Array): string {
    let result = "";

    for (const byte of bytes) {
        const digits = [];
        let value = byte;
        for (let i = 0; i < 4; i++) {
            digits.unshift(value % 6);
            value = Math.floor(value / 6);
        }
        result += digits.map((d) => ZWC_MAP[d]).join("");
    }

    return result;
}

/**
 * Converts Base-6 ZWC string back to bytes
 */
function zwcToBytes(zwcString: string): Uint8Array {
    const reverseMap: Record<string, number> = {};
    ZWC_MAP.forEach((char, index) => {
        reverseMap[char] = index;
    });

    const digits: number[] = [];
    for (const char of zwcString) {
        if (char in reverseMap) {
            digits.push(reverseMap[char]);
        }
    }

    if (digits.length % 4 !== 0) {
        throw new Error("Invalid ZWC data: length not divisible by 4");
    }

    const bytes: number[] = [];
    for (let i = 0; i < digits.length; i += 4) {
        const value = digits[i] * 216 +
            digits[i + 1] * 36 +
            digits[i + 2] * 6 +
            digits[i + 3];
        bytes.push(value);
    }

    return new Uint8Array(bytes);
}

/**
 * Distributes ZWC characters throughout text at natural break points
 * (line breaks, spaces, punctuation) for more stealthy embedding
 */
function distributeZWC(
    coverText: string,
    zwcPayload: string,
): string {
    const insertionPoints: number[] = [];

    for (let i = 0; i < coverText.length; i++) {
        const char = coverText[i];
        if (
            char === "\n" ||
            char === " " ||
            char === "." ||
            char === "," ||
            char === ";" ||
            char === ":" ||
            char === "!" ||
            char === "?" ||
            char === "\t"
        ) {
            insertionPoints.push(i + 1);
        }
    }

    if (insertionPoints.length === 0) {
        return coverText + START_SENTINEL + zwcPayload + END_SENTINEL;
    }

    const zwcChars = zwcPayload.split("");
    const chunksPerPoint = Math.ceil(zwcChars.length / insertionPoints.length);

    let result = "";
    let zwcIndex = 0;
    let lastPos = 0;

    for (let i = 0; i < insertionPoints.length && zwcIndex < zwcChars.length; i++) {
        const point = insertionPoints[i];

        result += coverText.substring(lastPos, point);

        const chunkSize = Math.min(chunksPerPoint, zwcChars.length - zwcIndex);
        for (let j = 0; j < chunkSize && zwcIndex < zwcChars.length; j++) {
            result += zwcChars[zwcIndex++];
        }

        lastPos = point;
    }

    result += coverText.substring(lastPos);

    return START_SENTINEL + result + END_SENTINEL;
}

/**
 * Encodes a secret message into a cover text using ZWC steganography
 *
 * @param coverText - The visible text that will contain the hidden message
 * @param secretMessage - The secret text to hide
 * @param password - Optional password for AES-256-CTR encryption
 * @param distribute - If true, distribute ZWC characters throughout text instead of appending
 * @returns The cover text with invisible ZWC payload embedded
 */
export async function encodeText(
    coverText: string,
    secretMessage: string,
    password?: string,
    distribute: boolean = false,
): Promise<StegaText> {
    const encoder = new TextEncoder();
    let data: Uint8Array = new Uint8Array(encoder.encode(secretMessage));

    data = new Uint8Array(await compress(data));

    if (password) {
        data = new Uint8Array(await encrypt(data, password));
    }

    // Header format: [1 byte: type][4 bytes: length][data]
    const header = new Uint8Array(1 + 4 + data.length);
    const view = new DataView(header.buffer);
    header[0] = PAYLOAD_TYPE_TEXT;
    view.setUint32(1, data.length, true);
    header.set(data, 5);

    const zwcPayload = bytesToZWC(header);

    if (distribute) {
        return asStegaText(distributeZWC(coverText, zwcPayload));
    }

    return asStegaText(coverText + START_SENTINEL + zwcPayload + END_SENTINEL);
}

/**
 * Extracts only valid ZWC characters from a string
 */
function extractZWCChars(str: string): string {
    const zwcSet = new Set(ZWC_MAP);
    let result = "";
    for (const char of str) {
        if (zwcSet.has(char as typeof ZWC_MAP[number])) {
            result += char;
        }
    }
    return result;
}

/**
 * Decodes a hidden message from text containing ZWC steganography
 *
 * @param stegaText - Text potentially containing hidden ZWC data
 * @param password - Password if the message was encrypted
 * @returns Object with visible text and decoded secret (or null if no hidden data)
 */
export async function decodeText(
    stegaText: string | StegaText,
    password?: string,
): Promise<{ visibleText: string; secretMessage: string | null }> {
    const startIdx = stegaText.indexOf(START_SENTINEL);

    if (startIdx === -1) {
        return {
            visibleText: stegaText.replace(ZWC_PATTERN, ""),
            secretMessage: null,
        };
    }

    const afterStart = stegaText.substring(startIdx + START_SENTINEL.length);
    const allZWC = extractZWCChars(afterStart);

    const visibleText = stegaText
        .replace(START_SENTINEL, "")
        .replace(END_SENTINEL, "")
        .replace(ZWC_PATTERN, "")
        .trim();

    // Header is 5 bytes: [1 byte: type][4 bytes: length] = 20 ZWC chars
    if (allZWC.length < 20) {
        return {
            visibleText,
            secretMessage: null,
        };
    }

    try {
        // Read header: type (1 byte = 4 ZWC) + length (4 bytes = 16 ZWC)
        const headerZWC = allZWC.substring(0, 20);
        const headerBytes = zwcToBytes(headerZWC);
        const payloadType = headerBytes[0];
        const view = new DataView(headerBytes.buffer, headerBytes.byteOffset);
        const dataLength = view.getUint32(1, true);

        if (payloadType !== PAYLOAD_TYPE_TEXT) {
            throw new Error(`Expected text payload (type ${PAYLOAD_TYPE_TEXT}), got type ${payloadType}`);
        }

        const dataZWCLength = dataLength * 4;
        const totalZWCNeeded = 20 + dataZWCLength;

        if (allZWC.length < totalZWCNeeded) {
            throw new Error("Incomplete data - payload appears truncated");
        }

        const dataZWC = allZWC.substring(20, totalZWCNeeded);
        let data = zwcToBytes(dataZWC);

        if (password) {
            data = await decrypt(data, password);
        }

        data = await decompress(data);

        const decoder = new TextDecoder("utf-8", { fatal: true });
        const secretMessage = decoder.decode(data);

        return { visibleText, secretMessage };
    } catch (error) {
        throw new Error(
            `Decoding failed: ${error instanceof Error ? error.message : String(error)}`,
        );
    }
}

/**
 * Encodes binary data (e.g., images) into a cover text using ZWC steganography
 *
 * @param coverText - The visible text that will contain the hidden data
 * @param binaryData - The binary data to hide (Uint8Array)
 * @param password - Optional password for AES-256-CTR encryption
 * @param distribute - If true, distribute ZWC characters throughout text instead of appending
 * @returns The cover text with invisible ZWC payload embedded
 */
export async function encodeBinary(
    coverText: string,
    binaryData: Uint8Array,
    password?: string,
    distribute: boolean = false,
): Promise<StegaText> {
    let data: Uint8Array = new Uint8Array(binaryData);

    data = new Uint8Array(await compress(data));

    if (password) {
        data = new Uint8Array(await encrypt(data, password));
    }

    // Header format: [1 byte: type][4 bytes: length][data]
    const header = new Uint8Array(1 + 4 + data.length);
    const view = new DataView(header.buffer);
    header[0] = PAYLOAD_TYPE_BINARY;
    view.setUint32(1, data.length, true);
    header.set(data, 5);

    const zwcPayload = bytesToZWC(header);

    if (distribute) {
        return asStegaText(distributeZWC(coverText, zwcPayload));
    }

    return asStegaText(coverText + START_SENTINEL + zwcPayload + END_SENTINEL);
}

/**
 * Decodes binary data from text containing ZWC steganography
 *
 * @param stegaText - Text potentially containing hidden ZWC data
 * @param password - Password if the data was encrypted
 * @returns Object with visible text and decoded binary data (or null if no hidden data)
 */
export async function decodeBinary(
    stegaText: string | StegaText,
    password?: string,
): Promise<{ visibleText: string; binaryData: Uint8Array | null }> {
    const startIdx = stegaText.indexOf(START_SENTINEL);

    if (startIdx === -1) {
        return {
            visibleText: stegaText.replace(ZWC_PATTERN, ""),
            binaryData: null,
        };
    }

    const afterStart = stegaText.substring(startIdx + START_SENTINEL.length);
    const allZWC = extractZWCChars(afterStart);

    const visibleText = stegaText
        .replace(START_SENTINEL, "")
        .replace(END_SENTINEL, "")
        .replace(ZWC_PATTERN, "")
        .trim();

    // Header is 5 bytes: [1 byte: type][4 bytes: length] = 20 ZWC chars
    if (allZWC.length < 20) {
        return {
            visibleText,
            binaryData: null,
        };
    }

    try {
        // Read header: type (1 byte = 4 ZWC) + length (4 bytes = 16 ZWC)
        const headerZWC = allZWC.substring(0, 20);
        const headerBytes = zwcToBytes(headerZWC);
        const payloadType = headerBytes[0];
        const view = new DataView(headerBytes.buffer, headerBytes.byteOffset);
        const dataLength = view.getUint32(1, true);

        if (payloadType !== PAYLOAD_TYPE_BINARY) {
            throw new Error(`Expected binary payload (type ${PAYLOAD_TYPE_BINARY}), got type ${payloadType}`);
        }

        const dataZWCLength = dataLength * 4;
        const totalZWCNeeded = 20 + dataZWCLength;

        if (allZWC.length < totalZWCNeeded) {
            throw new Error("Incomplete data - payload appears truncated");
        }

        const dataZWC = allZWC.substring(20, totalZWCNeeded);
        let data = zwcToBytes(dataZWC);

        if (password) {
            data = await decrypt(data, password);
        }

        data = await decompress(data);

        return { visibleText, binaryData: data };
    } catch (error) {
        throw new Error(
            `Decoding failed: ${error instanceof Error ? error.message : String(error)}`,
        );
    }
}

/**
 * Unified decode function that auto-detects payload type (text or binary)
 *
 * @param stegaText - Text potentially containing hidden ZWC data
 * @param password - Password if the data was encrypted
 * @returns Object with visible text and decoded data (text or binary based on payload type)
 */
export async function decode(
    stegaText: string | StegaText,
    password?: string,
): Promise<{
    visibleText: string;
    payloadType: "text" | "binary" | null;
    textData: string | null;
    binaryData: Uint8Array | null;
}> {
    const startIdx = stegaText.indexOf(START_SENTINEL);

    if (startIdx === -1) {
        return {
            visibleText: stegaText.replace(ZWC_PATTERN, ""),
            payloadType: null,
            textData: null,
            binaryData: null,
        };
    }

    const afterStart = stegaText.substring(startIdx + START_SENTINEL.length);
    const allZWC = extractZWCChars(afterStart);

    const visibleText = stegaText
        .replace(START_SENTINEL, "")
        .replace(END_SENTINEL, "")
        .replace(ZWC_PATTERN, "")
        .trim();

    // Header is 5 bytes: [1 byte: type][4 bytes: length] = 20 ZWC chars
    if (allZWC.length < 20) {
        return {
            visibleText,
            payloadType: null,
            textData: null,
            binaryData: null,
        };
    }

    try {
        // Read header: type (1 byte = 4 ZWC) + length (4 bytes = 16 ZWC)
        const headerZWC = allZWC.substring(0, 20);
        const headerBytes = zwcToBytes(headerZWC);
        const payloadType = headerBytes[0];
        const view = new DataView(headerBytes.buffer, headerBytes.byteOffset);
        const dataLength = view.getUint32(1, true);

        const dataZWCLength = dataLength * 4;
        const totalZWCNeeded = 20 + dataZWCLength;

        if (allZWC.length < totalZWCNeeded) {
            throw new Error("Incomplete data - payload appears truncated");
        }

        const dataZWC = allZWC.substring(20, totalZWCNeeded);
        let data = zwcToBytes(dataZWC);

        if (password) {
            data = await decrypt(data, password);
        }

        data = await decompress(data);

        if (payloadType === PAYLOAD_TYPE_TEXT) {
            const decoder = new TextDecoder("utf-8", { fatal: true });
            const textData = decoder.decode(data);
            return {
                visibleText,
                payloadType: "text",
                textData,
                binaryData: null,
            };
        } else if (payloadType === PAYLOAD_TYPE_BINARY) {
            return {
                visibleText,
                payloadType: "binary",
                textData: null,
                binaryData: data,
            };
        } else {
            throw new Error(`Unknown payload type: ${payloadType}`);
        }
    } catch (error) {
        throw new Error(
            `Decoding failed: ${error instanceof Error ? error.message : String(error)}`,
        );
    }
}

/**
 * Checks if text contains hidden ZWC steganography data
 */
export function hasHiddenData(text: string | StegaText): boolean {
    const startIdx = text.indexOf(START_SENTINEL);
    if (startIdx === -1) return false;

    const afterStart = text.substring(startIdx + START_SENTINEL.length);
    const zwcSet = new Set(ZWC_MAP);
    let zwcCount = 0;
    for (const char of afterStart) {
        if (zwcSet.has(char as typeof ZWC_MAP[number])) {
            zwcCount++;
            if (zwcCount >= 16) return true;
        }
    }
    return false;
}

/**
 * Strips all ZWC characters from text (removes any hidden data)
 */
export function stripZWC(text: string): string {
    return text.replace(ZWC_PATTERN, "");
}

/**
 * Visualizes hidden ZWC characters for debugging
 * Replaces invisible characters with visible colored representations
 */
export interface VisualizedChar {
    char: string;
    isZWC: boolean;
    type?: "ZWSP" | "ZWNJ" | "ZWJ" | "BOM" | "WJ" | "FUN" | "START" | "END";
    value?: number;
}

export function visualizeZWC(text: string): VisualizedChar[] {
    const result: VisualizedChar[] = [];

    const zwcNames: Record<
        string,
        { type: VisualizedChar["type"]; value: number }
    > = {
        "\u200b": { type: "ZWSP", value: 0 },
        "\u200c": { type: "ZWNJ", value: 1 },
        "\u200d": { type: "ZWJ", value: 2 },
        "\ufeff": { type: "BOM", value: 3 },
        "\u2060": { type: "WJ", value: 4 },
        "\u2061": { type: "FUN", value: 5 },
    };

    let i = 0;
    while (i < text.length) {
        const char = text[i];

        if (text.substring(i, i + 3) === START_SENTINEL) {
            result.push({ char: "[START]", isZWC: true, type: "START" });
            i += 3;
            continue;
        }

        if (text.substring(i, i + 3) === END_SENTINEL) {
            result.push({ char: "[END]", isZWC: true, type: "END" });
            i += 3;
            continue;
        }

        if (char in zwcNames) {
            const info = zwcNames[char];
            result.push({
                char: `[${info.type}]`,
                isZWC: true,
                type: info.type,
                value: info.value,
            });
        } else {
            result.push({ char, isZWC: false });
        }

        i++;
    }

    return result;
}

/**
 * Returns statistics about hidden data in text
 */
export interface ZWCStats {
    hasHiddenData: boolean;
    visibleLength: number;
    zwcCount: number;
    estimatedPayloadBytes: number;
    breakdown: Record<string, number>;
}

export function analyzeZWC(text: string): ZWCStats {
    const hasHidden = hasHiddenData(text);
    const visible = stripZWC(text);

    const breakdown: Record<string, number> = {
        ZWSP: 0,
        ZWNJ: 0,
        ZWJ: 0,
        BOM: 0,
        WJ: 0,
        FUN: 0,
    };

    let zwcCount = 0;
    for (const char of text) {
        switch (char) {
            case "\u200b":
                breakdown.ZWSP++;
                zwcCount++;
                break;
            case "\u200c":
                breakdown.ZWNJ++;
                zwcCount++;
                break;
            case "\u200d":
                breakdown.ZWJ++;
                zwcCount++;
                break;
            case "\ufeff":
                breakdown.BOM++;
                zwcCount++;
                break;
            case "\u2060":
                breakdown.WJ++;
                zwcCount++;
                break;
            case "\u2061":
                breakdown.FUN++;
                zwcCount++;
                break;
        }
    }

    // Each byte = 4 ZWC chars, minus sentinel overhead (6 chars)
    const payloadZWC = Math.max(0, zwcCount - 6);
    const estimatedPayloadBytes = Math.floor(payloadZWC / 4);

    return {
        hasHiddenData: hasHidden,
        visibleLength: visible.length,
        zwcCount,
        estimatedPayloadBytes,
        breakdown,
    };
}

export const MAX_SECRET_LENGTH = 50000; // 50KB uncompressed secret
export const MAX_COVER_LENGTH = 100000; // 100KB cover text
