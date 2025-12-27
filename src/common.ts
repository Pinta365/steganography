/**
 * Common utilities shared between image and text steganography
 * Includes XOR encryption, bit/byte conversion, and validation functions
 */

/**
 * XOR encrypts data using a cyclic password key
 * Each byte is XORed with the corresponding byte from the password (repeated as needed)
 */
export function xorEncrypt(data: Uint8Array, password: string): Uint8Array {
    if (password.length === 0) return data;

    const passwordBytes = new TextEncoder().encode(password);
    const result = new Uint8Array(data.length);

    for (let i = 0; i < data.length; i++) {
        result[i] = data[i] ^ passwordBytes[i % passwordBytes.length];
    }

    return result;
}

/**
 * XOR decrypts data (XOR is its own inverse)
 */
export function xorDecrypt(data: Uint8Array, password: string): Uint8Array {
    return xorEncrypt(data, password);
}

/**
 * Converts a byte array to a bit array
 * Each byte becomes 8 bits (LSB first)
 */
export function bytesToBits(bytes: Uint8Array): Uint8Array {
    const bits = new Uint8Array(bytes.length * 8);

    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i];
        for (let j = 0; j < 8; j++) {
            bits[i * 8 + j] = (byte >> j) & 1;
        }
    }

    return bits;
}

/**
 * Converts a bit array back to bytes
 * 8 bits become 1 byte (LSB first)
 */
export function bitsToBytes(bits: Uint8Array): Uint8Array {
    const byteCount = Math.floor(bits.length / 8);
    const bytes = new Uint8Array(byteCount);

    for (let i = 0; i < byteCount; i++) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
            const bitIndex = i * 8 + j;
            if (bitIndex < bits.length) {
                byte |= (bits[bitIndex] & 1) << j;
            }
        }
        bytes[i] = byte;
    }

    return bytes;
}

/**
 * Maximum file size limits (in bytes)
 */
export const MAX_IMAGE_SIZE = 50 * 1024 * 1024; // 50MB
export const MAX_EMBED_FILE_SIZE = 10 * 1024 * 1024; // 10MB
export const MAX_MESSAGE_LENGTH = 10 * 1024 * 1024; // 10MB
export const MAX_IMAGE_DIMENSION = 10000; // 10,000 pixels
export const MAX_FILENAME_LENGTH = 255;

/**
 * Validates image dimensions to prevent memory exhaustion
 */
export function validateImageDimensions(
    width: number,
    height: number,
): void {
    if (!Number.isInteger(width) || !Number.isInteger(height)) {
        throw new Error(
            `Invalid image dimensions: width and height must be integers. Got width: ${width}, height: ${height}`,
        );
    }
    if (width <= 0 || height <= 0) {
        throw new Error(
            `Invalid image dimensions: width and height must be positive. Got width: ${width}, height: ${height}`,
        );
    }
    if (width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION) {
        throw new Error(
            `Image dimensions too large: ${width}x${height} pixels (maximum ${MAX_IMAGE_DIMENSION}x${MAX_IMAGE_DIMENSION} pixels). ` +
                `Consider resizing the image or increasing MAX_IMAGE_DIMENSION.`,
        );
    }
    const pixelCount = width * height;
    const maxPixels = MAX_IMAGE_DIMENSION * MAX_IMAGE_DIMENSION;
    if (pixelCount > maxPixels) {
        throw new Error(
            `Image size too large: ${pixelCount} pixels (maximum ${maxPixels} pixels, ${MAX_IMAGE_DIMENSION}x${MAX_IMAGE_DIMENSION}). ` +
                `Consider resizing the image or increasing MAX_IMAGE_DIMENSION.`,
        );
    }
}

/**
 * Sanitizes a filename to prevent path traversal and XSS attacks
 * Removes path separators, limits length, and validates characters
 */
export function sanitizeFilename(filename: string): string {
    if (!filename || filename.length === 0) {
        return "file";
    }

    let sanitized = filename
        .replace(/[/\\?%*:|"<>]/g, "")
        .replace(/^\.+/, "")
        .trim();

    if (sanitized.length === 0) {
        return "file";
    }

    if (sanitized.length > MAX_FILENAME_LENGTH) {
        const ext = sanitized.lastIndexOf(".");
        if (ext > 0) {
            const name = sanitized.substring(0, ext);
            const extension = sanitized.substring(ext);
            sanitized = name.substring(0, MAX_FILENAME_LENGTH - extension.length) +
                extension;
        } else {
            sanitized = sanitized.substring(0, MAX_FILENAME_LENGTH);
        }
    }

    return sanitized;
}

/**
 * Validates file size before processing
 */
export function validateFileSize(size: number, maxSize: number): void {
    if (size <= 0) {
        throw new Error(
            `Invalid file size: ${size} bytes. File size must be positive.`,
        );
    }
    if (size > maxSize) {
        const sizeMB = (size / (1024 * 1024)).toFixed(2);
        const maxMB = (maxSize / (1024 * 1024)).toFixed(2);
        throw new Error(
            `File too large: ${sizeMB}MB (${size} bytes), maximum: ${maxMB}MB (${maxSize} bytes). ` +
                `Consider compressing the file or increasing the maximum size limit.`,
        );
    }
}
