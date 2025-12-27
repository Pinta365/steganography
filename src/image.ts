/**
 * Image steganography utilities
 * Supports both pixel-domain (LSB for lossless formats) and coefficient-domain (DCT for JPEG) steganography
 */

import { Image, type JPEGComponentCoefficients, type JPEGQuantizedCoefficients } from "@cross/image";

// Re-export Image type so users don't need to import @cross/image
export type { Image };
import {
    bitsToBytes,
    bytesToBits,
    MAX_EMBED_FILE_SIZE,
    MAX_FILENAME_LENGTH,
    MAX_MESSAGE_LENGTH,
    sanitizeFilename,
    validateImageDimensions,
} from "./common.ts";

/**
 * Detects image format from file data using @cross/image's format handlers
 * Returns format name or null if unknown
 * Uses the same detection logic as Image.decode() but without decoding
 */
export function detectImageFormat(data: Uint8Array): string | null {
    const formats = Image.getFormats();

    for (const format of formats) {
        if (format.canDecode(data)) {
            return format.name;
        }
    }

    return null;
}

/**
 * Checks if a format is lossy (will destroy pixel-domain embedding data on re-encoding)
 */
export function isLossyFormat(format: string | null): boolean {
    if (!format) return false;
    const formatLower = format.toLowerCase();
    const lossyFormats = ["jpeg", "jpg", "webp"];
    return lossyFormats.includes(formatLower);
}

/**
 * Gets a recommended output format based on input format
 * Always returns a lossless format to preserve pixel-domain embedding data
 */
export function getRecommendedOutputFormat(inputFormat: string | null): {
    format: string;
    reason: string;
    useWebP?: boolean;
} {
    const useWebP = typeof OffscreenCanvas !== "undefined";

    if (inputFormat && isLossyFormat(inputFormat)) {
        return {
            format: useWebP ? "webp" : "png",
            reason: `Original format (${inputFormat.toUpperCase()}) is lossy. Saving as ${
                useWebP ? "WebP lossless" : "PNG"
            } to preserve hidden data. File size may increase.`,
            useWebP,
        };
    }

    return {
        format: useWebP ? "webp" : "png",
        reason: `${useWebP ? "WebP lossless" : "PNG"} format preserves hidden data perfectly.`,
        useWebP,
    };
}

/**
 * Embeds message bits into the LSB of image pixels
 * Uses RGB channels only (skips alpha for better visual quality)
 * @param bitDepth Number of bits to use per byte (1-4)
 */
export function embedLSB(
    imageData: Uint8Array,
    messageBits: Uint8Array,
    bitDepth: number = 1,
): Uint8Array {
    if (bitDepth < 1 || bitDepth > 4) {
        throw new Error(
            `Invalid bit depth: ${bitDepth}. Bit depth must be between 1 and 4 (inclusive). ` +
                `Higher bit depth increases capacity but may reduce image quality.`,
        );
    }

    const result = new Uint8Array(imageData);
    const maxBits = Math.floor((imageData.length / 4) * 3) * bitDepth;

    if (messageBits.length > maxBits) {
        const maxBytes = Math.floor(maxBits / 8);
        const gotBytes = Math.ceil(messageBits.length / 8);
        throw new Error(
            `Message too large for image capacity. ` +
                `Required: ${messageBits.length} bits (${gotBytes} bytes), ` +
                `Available: ${maxBits} bits (${maxBytes} bytes). ` +
                `Try: shorter message, larger image, or higher bitDepth (1-4).`,
        );
    }

    const mask = 0xFF << bitDepth;

    let bitIndex = 0;
    for (let i = 0; i < imageData.length && bitIndex < messageBits.length; i++) {
        if (i % 4 === 3) continue;

        let bitsToEmbed = 0;
        for (let j = 0; j < bitDepth && bitIndex < messageBits.length; j++) {
            const bit = messageBits[bitIndex] & 1;
            bitsToEmbed |= bit << j;
            bitIndex++;
        }

        result[i] = (result[i] & mask) | bitsToEmbed;
    }

    return result;
}

/**
 * Extracts LSB bits from image pixels
 * Uses RGB channels only (skips alpha)
 * @param bitDepth Number of bits to extract per byte (1-4)
 * @param bitOffset Number of bits to skip before extracting (default: 0)
 */
export function extractLSB(
    imageData: Uint8Array,
    bitCount: number,
    bitDepth: number = 1,
    bitOffset: number = 0,
): Uint8Array {
    if (bitDepth < 1 || bitDepth > 4) {
        throw new Error(
            `Invalid bit depth: ${bitDepth}. Bit depth must be between 1 and 4 (inclusive). ` +
                `Higher bit depth increases capacity but may reduce image quality.`,
        );
    }

    const bits = new Uint8Array(bitCount);
    const maxBits = Math.floor((imageData.length / 4) * 3) * bitDepth;
    const actualBitCount = Math.min(bitCount, maxBits - bitOffset);

    let bitIndex = 0;
    let bitsSkipped = 0;
    for (let i = 0; i < imageData.length && bitIndex < actualBitCount; i++) {
        if (i % 4 === 3) continue;

        for (let j = 0; j < bitDepth; j++) {
            if (bitsSkipped < bitOffset) {
                bitsSkipped++;
                continue;
            }
            if (bitIndex >= actualBitCount) break;
            bits[bitIndex] = (imageData[i] >> j) & 1;
            bitIndex++;
        }
    }

    return bits;
}

/**
 * Generates a Bit-Sieve visualization
 * Creates a high-contrast visualization by amplifying LSB differences
 * Uses a checkerboard pattern to make LSB changes more visible
 */
export function generateBitSieve(imageData: Uint8Array): Uint8Array {
    const result = new Uint8Array(imageData.length);
    const width = Math.sqrt(imageData.length / 4);

    for (let i = 0; i < imageData.length; i += 4) {
        const pixelIndex = i / 4;
        const x = pixelIndex % width;
        const y = Math.floor(pixelIndex / width);

        const rLSB = imageData[i] & 1;
        const gLSB = imageData[i + 1] & 1;
        const bLSB = imageData[i + 2] & 1;

        const checker = (x + y) % 2 === 0 ? 1 : 0;

        const rValue = rLSB ? (checker ? 255 : 200) : (checker ? 50 : 0);
        const gValue = gLSB ? (checker ? 255 : 200) : (checker ? 50 : 0);
        const bValue = bLSB ? (checker ? 255 : 200) : (checker ? 50 : 0);

        result[i] = rValue;
        result[i + 1] = gValue;
        result[i + 2] = bValue;
        result[i + 3] = 255;
    }

    return result;
}

/**
 * Generates LSB statistics for display
 * Returns counts of LSB=1 vs LSB=0 per channel
 * Optionally compares with original to show how many bits were changed
 */
export function generateLSBStats(
    imageData: Uint8Array,
    originalData?: Uint8Array,
): {
    red: { ones: number; zeros: number; changed?: number };
    green: { ones: number; zeros: number; changed?: number };
    blue: { ones: number; zeros: number; changed?: number };
    total: { ones: number; zeros: number; changed?: number };
} {
    let redOnes = 0, redZeros = 0, redChanged = 0;
    let greenOnes = 0, greenZeros = 0, greenChanged = 0;
    let blueOnes = 0, blueZeros = 0, blueChanged = 0;

    for (let i = 0; i < imageData.length; i += 4) {
        const rLSB = imageData[i] & 1;
        const gLSB = imageData[i + 1] & 1;
        const bLSB = imageData[i + 2] & 1;

        if (rLSB) redOnes++;
        else redZeros++;
        if (gLSB) greenOnes++;
        else greenZeros++;
        if (bLSB) blueOnes++;
        else blueZeros++;

        if (originalData && i < originalData.length) {
            const origRLSB = originalData[i] & 1;
            const origGLSB = originalData[i + 1] & 1;
            const origBLSB = originalData[i + 2] & 1;

            if (rLSB !== origRLSB) redChanged++;
            if (gLSB !== origGLSB) greenChanged++;
            if (bLSB !== origBLSB) blueChanged++;
        }
    }

    const result: {
        red: { ones: number; zeros: number; changed?: number };
        green: { ones: number; zeros: number; changed?: number };
        blue: { ones: number; zeros: number; changed?: number };
        total: { ones: number; zeros: number; changed?: number };
    } = {
        red: { ones: redOnes, zeros: redZeros },
        green: { ones: greenOnes, zeros: greenZeros },
        blue: { ones: blueOnes, zeros: blueZeros },
        total: {
            ones: redOnes + greenOnes + blueOnes,
            zeros: redZeros + greenZeros + blueZeros,
        },
    };

    if (originalData) {
        result.red.changed = redChanged;
        result.green.changed = greenChanged;
        result.blue.changed = blueChanged;
        result.total.changed = redChanged + greenChanged + blueChanged;
    }

    return result;
}

/**
 * Prepares a binary header for file embedding
 * Format: [Magic(1), NameLen(1), Name(N), FileSize(4)]
 */
export function prepareFileHeader(
    fileName: string,
    fileSize: number,
): Uint8Array {
    const fileNameBytes = new TextEncoder().encode(fileName);
    const header = new Uint8Array(1 + 1 + fileNameBytes.length + 4);
    const view = new DataView(header.buffer);

    header[0] = 0x55;
    header[1] = fileNameBytes.length;
    header.set(fileNameBytes, 2);
    view.setUint32(2 + fileNameBytes.length, fileSize, true);

    return header;
}

/**
 * Parses a file header from bit array (converted to bytes)
 * Returns header info or null if magic byte not found
 */
export function parseFileHeader(
    bytes: Uint8Array,
): { fileName: string; fileSize: number; payloadOffset: number } | null {
    if (bytes.length < 2 || bytes[0] !== 0x55) {
        return null;
    }

    const nameLen = bytes[1];
    if (nameLen > MAX_FILENAME_LENGTH || bytes.length < 2 + nameLen + 4) {
        return null;
    }

    const fileNameBytes = bytes.slice(2, 2 + nameLen);
    const fileName = new TextDecoder("utf-8", { fatal: false }).decode(
        fileNameBytes,
    );

    if (!fileName || fileName.length === 0) {
        return null;
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset);
    const fileSize = view.getUint32(2 + nameLen, true);

    if (fileSize > MAX_EMBED_FILE_SIZE || fileSize <= 0) {
        return null;
    }

    const payloadOffset = 2 + nameLen + 4;

    if (bytes.length < payloadOffset + fileSize) {
        return null;
    }

    return {
        fileName: sanitizeFilename(fileName),
        fileSize,
        payloadOffset,
    };
}

/**
 * Calculates the bit capacity of an image
 * Returns the number of bytes that can be hidden (using RGB channels)
 * @param bitDepth Number of bits to use per byte (1-4)
 */
export function calculateBitCapacity(
    width: number,
    height: number,
    bitDepth: number = 1,
): number {
    validateImageDimensions(width, height);
    return Math.floor((width * height * 3 * bitDepth) / 8);
}

/**
 * Calculates the embedding capacity of JPEG coefficients
 * Uses non-zero AC coefficients (index 1-63) for embedding
 * DC coefficients (index 0) are skipped as they're too visually sensitive
 * @param coefficients JPEG quantized coefficients
 * @param useChroma Whether to also use chroma (Cb, Cr) components
 * @returns Number of bytes that can be hidden
 */
export function calculateJpegCoefficientCapacity(
    coefficients: JPEGQuantizedCoefficients,
    useChroma: boolean = true,
): number {
    let bitCount = 0;

    for (const component of coefficients.components) {
        if (!useChroma && component.id !== 1) continue;

        for (const row of component.blocks) {
            for (const block of row) {
                for (let i = 1; i < 64; i++) {
                    if (block[i] !== 0 && block[i] !== 1 && block[i] !== -1) {
                        bitCount++;
                    }
                }
            }
        }
    }

    return Math.floor(bitCount / 8);
}

/**
 * Embeds message bits into JPEG coefficient LSBs
 * Uses non-zero AC coefficients with magnitude > 1 for embedding
 * Modifies coefficients in-place
 * @param coefficients JPEG quantized coefficients (will be modified)
 * @param messageBits Bits to embed
 * @param useChroma Whether to also use chroma (Cb, Cr) components
 * @returns The modified coefficients
 */
export function embedInCoefficients(
    coefficients: JPEGQuantizedCoefficients,
    messageBits: Uint8Array,
    useChroma: boolean = true,
): JPEGQuantizedCoefficients {
    let bitIndex = 0;

    for (const component of coefficients.components) {
        if (bitIndex >= messageBits.length) break;

        if (!useChroma && component.id !== 1) continue;

        for (const row of component.blocks) {
            if (bitIndex >= messageBits.length) break;

            for (const block of row) {
                if (bitIndex >= messageBits.length) break;

                for (let i = 1; i < 64 && bitIndex < messageBits.length; i++) {
                    const coeff = block[i];

                    if (coeff !== 0 && coeff !== 1 && coeff !== -1) {
                        const messageBit = messageBits[bitIndex] & 1;
                        const coeffLSB = Math.abs(coeff) & 1;

                        if (coeffLSB !== messageBit) {
                            if (coeff > 0) {
                                block[i] = messageBit ? (coeff | 1) : (coeff & ~1);
                                if (block[i] === 0 || block[i] === 1) {
                                    block[i] = coeff;
                                    continue;
                                }
                            } else {
                                const absCoeff = -coeff;
                                const newAbs = messageBit ? (absCoeff | 1) : (absCoeff & ~1);
                                if (newAbs === 0 || newAbs === 1) {
                                    continue;
                                }
                                block[i] = -newAbs;
                            }
                        }
                        bitIndex++;
                    }
                }
            }
        }
    }

    if (bitIndex < messageBits.length) {
        const capacityBytes = Math.floor(bitIndex / 8);
        const requiredBytes = Math.ceil(messageBits.length / 8);
        throw new Error(
            `Message too large for JPEG coefficient capacity. ` +
                `Required: ${messageBits.length} bits (${requiredBytes} bytes), ` +
                `Available: ${bitIndex} bits (${capacityBytes} bytes). ` +
                `Try: shorter message, larger image, or enable chroma components (useChroma: true).`,
        );
    }

    return coefficients;
}

/**
 * Extracts LSB bits from JPEG coefficient data
 * @param coefficients JPEG quantized coefficients
 * @param bitCount Number of bits to extract
 * @param useChroma Whether to also extract from chroma (Cb, Cr) components
 * @returns Extracted bits
 */
export function extractFromCoefficients(
    coefficients: JPEGQuantizedCoefficients,
    bitCount: number,
    useChroma: boolean = true,
): Uint8Array {
    const bits = new Uint8Array(bitCount);
    let bitIndex = 0;

    for (const component of coefficients.components) {
        if (bitIndex >= bitCount) break;

        if (!useChroma && component.id !== 1) continue;

        for (const row of component.blocks) {
            if (bitIndex >= bitCount) break;

            for (const block of row) {
                if (bitIndex >= bitCount) break;

                for (let i = 1; i < 64 && bitIndex < bitCount; i++) {
                    const coeff = block[i];

                    if (coeff !== 0 && coeff !== 1 && coeff !== -1) {
                        bits[bitIndex] = Math.abs(coeff) & 1;
                        bitIndex++;
                    }
                }
            }
        }
    }

    return bits;
}

/**
 * Generates LSB statistics for JPEG coefficients
 * Returns counts of LSB=1 vs LSB=0 per component
 */
export function generateJpegCoefficientStats(
    coefficients: JPEGQuantizedCoefficients,
): {
    luminance: { ones: number; zeros: number; total: number };
    chroma: { ones: number; zeros: number; total: number };
    total: { ones: number; zeros: number; usable: number };
} {
    let lumOnes = 0, lumZeros = 0, lumTotal = 0;
    let chromaOnes = 0, chromaZeros = 0, chromaTotal = 0;

    for (const component of coefficients.components) {
        const isLuminance = component.id === 1;

        for (const row of component.blocks) {
            for (const block of row) {
                for (let i = 1; i < 64; i++) {
                    const coeff = block[i];

                    if (coeff !== 0 && coeff !== 1 && coeff !== -1) {
                        const lsb = Math.abs(coeff) & 1;
                        if (isLuminance) {
                            if (lsb) lumOnes++;
                            else lumZeros++;
                            lumTotal++;
                        } else {
                            if (lsb) chromaOnes++;
                            else chromaZeros++;
                            chromaTotal++;
                        }
                    }
                }
            }
        }
    }

    return {
        luminance: { ones: lumOnes, zeros: lumZeros, total: lumTotal },
        chroma: { ones: chromaOnes, zeros: chromaZeros, total: chromaTotal },
        total: {
            ones: lumOnes + chromaOnes,
            zeros: lumZeros + chromaZeros,
            usable: lumTotal + chromaTotal,
        },
    };
}

export async function extractJpegCoefficients(
    jpegData: Uint8Array,
): Promise<JPEGQuantizedCoefficients | null> {
    const coeffs = await Image.extractCoefficients(jpegData, "jpeg");
    if (coeffs && coeffs.format === "jpeg") {
        return coeffs as JPEGQuantizedCoefficients;
    }
    return null;
}

export async function encodeJpegFromCoefficients(
    coefficients: JPEGQuantizedCoefficients,
): Promise<Uint8Array> {
    return await Image.encodeFromCoefficients(coefficients, "jpeg");
}

/**
 * Deep clones JPEG coefficients to avoid modifying the original
 */
export function cloneJpegCoefficients(
    coefficients: JPEGQuantizedCoefficients,
): JPEGQuantizedCoefficients {
    return {
        ...coefficients,
        components: coefficients.components.map(
            (comp: JPEGComponentCoefficients) => ({
                ...comp,
                blocks: comp.blocks.map((row: Int32Array[]) => row.map((block: Int32Array) => new Int32Array(block))),
            }),
        ),
        quantizationTables: coefficients.quantizationTables.map((table) => table instanceof Uint8Array ? new Uint8Array(table) : [...table]),
    };
}

/**
 * Options for image encoding functions
 */
export interface ImageEncodeOptions {
    /**
     * Maximum payload size in bytes
     * If not specified, uses calculated capacity based on image size and bitDepth
     */
    maxPayloadBytes?: number;
    /**
     * Maximum message/data length in bytes (before embedding)
     * If not specified, uses MAX_MESSAGE_LENGTH (10MB)
     */
    maxMessageLength?: number;
    /**
     * Whether to throw an error if payload exceeds capacity (default: true)
     * If false, will only warn but still attempt encoding
     */
    strictCapacity?: boolean;
}

/**
 * Helper: Embeds a text message into image data using LSB
 * Automatically handles text-to-bits conversion
 *
 * @param imageData - RGBA image data (Uint8Array)
 * @param message - Text message to embed
 * @param bitDepth - Number of bits per pixel (1-4, default: 1)
 * @param options - Optional encoding options (capacity limits, strict mode)
 * @returns Modified image data with embedded message
 */
export function embedTextInImage(
    imageData: Uint8Array,
    message: string,
    bitDepth: number = 1,
    options?: ImageEncodeOptions,
): Uint8Array {
    const encoder = new TextEncoder();
    const messageBytes = encoder.encode(message);

    // Validate message length
    const maxMessageLength = options?.maxMessageLength ?? MAX_MESSAGE_LENGTH;
    if (messageBytes.length > maxMessageLength) {
        throw new Error(
            `Message too long. ${messageBytes.length} bytes, maximum: ${maxMessageLength} bytes. ` +
                `Increase maxMessageLength option if needed.`,
        );
    }

    // Calculate capacity
    const pixels = imageData.length / 4;
    const rgbChannels = pixels * 3; // Skip alpha
    const capacityBytes = Math.floor((rgbChannels * bitDepth) / 8);
    const maxCapacity = options?.maxPayloadBytes ?? capacityBytes;
    const strictMode = options?.strictCapacity ?? true;

    // Check capacity (message + 4-byte header)
    const requiredBytes = messageBytes.length + 4;
    if (requiredBytes > maxCapacity) {
        const message = `Message too large. ${requiredBytes} bytes required, capacity: ${maxCapacity} bytes. ` +
            `Try: shorter message, larger image, higher bitDepth (1-4), or increase maxPayloadBytes option.`;

        if (strictMode) {
            throw new Error(message);
        } else {
            console.warn(`⚠ ${message} Proceeding anyway...`);
        }
    }

    // Prepend 4-byte length header (little-endian)
    const header = new Uint8Array(4);
    const view = new DataView(header.buffer);
    view.setUint32(0, messageBytes.length, true);

    // Combine header + message
    const dataWithHeader = new Uint8Array(4 + messageBytes.length);
    dataWithHeader.set(header, 0);
    dataWithHeader.set(messageBytes, 4);

    const messageBits = bytesToBits(dataWithHeader);
    return embedLSB(imageData, messageBits, bitDepth);
}

/**
 * Helper: Extracts a text message from image data using LSB
 * Automatically handles bits-to-text conversion
 *
 * @param imageData - RGBA image data (Uint8Array)
 * @param bitDepth - Number of bits per pixel (1-4, default: 1)
 * @returns Extracted text message
 */
export function extractTextFromImage(
    imageData: Uint8Array,
    bitDepth: number = 1,
): string {
    // First extract 4 bytes (32 bits) for length header
    const headerBits = extractLSB(imageData, 32, bitDepth);
    const headerBytes = bitsToBytes(headerBits);
    const view = new DataView(headerBytes.buffer);
    const messageLength = view.getUint32(0, true);

    // Extract the actual message
    const messageBits = extractLSB(imageData, messageLength * 8, bitDepth, 32);
    const messageBytes = bitsToBytes(messageBits);
    const decoder = new TextDecoder("utf-8", { fatal: true });
    return decoder.decode(messageBytes);
}

/**
 * Helper: Embeds binary data into image data using LSB
 * Automatically handles bytes-to-bits conversion
 *
 * @param imageData - RGBA image data (Uint8Array)
 * @param data - Binary data to embed (Uint8Array)
 * @param bitDepth - Number of bits per pixel (1-4, default: 1)
 * @param options - Optional encoding options (capacity limits, strict mode)
 * @returns Modified image data with embedded data
 */
export function embedDataInImage(
    imageData: Uint8Array,
    data: Uint8Array,
    bitDepth: number = 1,
    options?: ImageEncodeOptions,
): Uint8Array {
    // Validate data length
    const maxMessageLength = options?.maxMessageLength ?? MAX_MESSAGE_LENGTH;
    if (data.length > maxMessageLength) {
        throw new Error(
            `Data too large. ${data.length} bytes, maximum: ${maxMessageLength} bytes. ` +
                `Increase maxMessageLength option if needed.`,
        );
    }

    // Calculate capacity
    const pixels = imageData.length / 4;
    const rgbChannels = pixels * 3; // Skip alpha
    const capacityBytes = Math.floor((rgbChannels * bitDepth) / 8);
    const maxCapacity = options?.maxPayloadBytes ?? capacityBytes;
    const strictMode = options?.strictCapacity ?? true;

    // Check capacity
    if (data.length > maxCapacity) {
        const message = `Data too large. ${data.length} bytes, capacity: ${maxCapacity} bytes. ` +
            `Try: smaller data, larger image, higher bitDepth (1-4), or increase maxPayloadBytes option.`;

        if (strictMode) {
            throw new Error(message);
        } else {
            console.warn(`⚠ ${message} Proceeding anyway...`);
        }
    }

    const dataBits = bytesToBits(data);
    return embedLSB(imageData, dataBits, bitDepth);
}

/**
 * Helper: Extracts binary data from image data using LSB
 * Automatically handles bits-to-bytes conversion
 *
 * @param imageData - RGBA image data (Uint8Array)
 * @param dataLength - Length of the data in bytes
 * @param bitDepth - Number of bits per pixel (1-4, default: 1)
 * @returns Extracted binary data
 */
export function extractDataFromImage(
    imageData: Uint8Array,
    dataLength: number,
    bitDepth: number = 1,
): Uint8Array {
    const bitCount = dataLength * 8;
    const extractedBits = extractLSB(imageData, bitCount, bitDepth);
    return bitsToBytes(extractedBits);
}

/**
 * Helper: Embeds binary data into JPEG coefficients using DCT coefficient-domain embedding
 * Automatically handles bytes-to-bits conversion
 *
 * @param coefficients - JPEG quantized coefficients (will be modified)
 * @param data - Binary data to embed (Uint8Array)
 * @param useChroma - Whether to also use chroma (Cb, Cr) components (default: true)
 * @returns The modified coefficients
 */
export function embedDataInJpegCoefficients(
    coefficients: JPEGQuantizedCoefficients,
    data: Uint8Array,
    useChroma: boolean = true,
): JPEGQuantizedCoefficients {
    const dataBits = bytesToBits(data);
    return embedInCoefficients(coefficients, dataBits, useChroma);
}

/**
 * Helper: Extracts binary data from JPEG coefficients using DCT coefficient-domain embedding
 * Automatically handles bits-to-bytes conversion
 *
 * @param coefficients - JPEG quantized coefficients
 * @param maxBytes - Maximum number of bytes to extract
 * @param useChroma - Whether to also extract from chroma (Cb, Cr) components (default: true)
 * @returns Extracted binary data
 */
export function extractDataFromJpegCoefficients(
    coefficients: JPEGQuantizedCoefficients,
    maxBytes: number,
    useChroma: boolean = true,
): Uint8Array {
    const maxBits = maxBytes * 8;
    const extractedBits = extractFromCoefficients(coefficients, maxBits, useChroma);
    return bitsToBytes(extractedBits);
}

/**
 * Decodes image file data into an Image object
 * Wrapper around @cross/image's Image.decode() to avoid requiring users to import it
 *
 * @param imageData - Image file data (PNG, JPEG, WebP, etc.)
 * @returns Image object with width, height, and RGBA data
 */
export async function decodeImage(imageData: Uint8Array): Promise<Image> {
    return await Image.decode(imageData);
}

/**
 * Encoding options for different image formats
 * See @cross/image documentation for format-specific option types:
 * - PNG/APNG: PNGEncoderOptions (compressionLevel)
 * - WebP: WebPEncoderOptions (quality, lossless)
 * - TIFF: TIFFEncoderOptions (compression, grayscale, rgb, cmyk)
 * - Other formats: See @cross/image types
 */
// EncodeOptions for image encoding is ImageEncodeOptions (see above)
// This type is for @cross/image's encode() method options
export type ImageFormatEncodeOptions = unknown;

/**
 * Encodes an Image object to file data
 * Wrapper around @cross/image's Image.encode() to avoid requiring users to import it
 *
 * @param image - Image object
 * @param format - Output format (png, jpeg, webp, etc.)
 * @param options - Optional encoding options (format-specific)
 * @returns Encoded image file data
 */
export async function encodeImage(
    image: Image,
    format: string,
    options?: ImageFormatEncodeOptions,
): Promise<Uint8Array> {
    // @cross/image's encode method accepts options as second parameter
    return await image.encode(format, options);
}

/**
 * Creates a new Image object
 * Wrapper around @cross/image's Image constructor to avoid requiring users to import it
 *
 * @param width - Image width in pixels
 * @param height - Image height in pixels
 * @param data - RGBA image data (Uint8Array)
 * @returns Image object
 */
export function createImage(width: number, height: number, data: Uint8Array): Image {
    // Use Image.fromRGBA() instead of constructor
    return Image.fromRGBA(width, height, data);
}
