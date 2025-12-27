import { test } from "@cross/test";
import { assert, assertEquals, assertThrows } from "@std/assert";
import {
    detectImageFormat,
    getRecommendedOutputFormat,
    isLossyFormat,
    MAX_EMBED_FILE_SIZE,
    MAX_IMAGE_DIMENSION,
    sanitizeFilename,
    validateFileSize,
    validateImageDimensions,
    xorDecrypt,
    xorEncrypt,
} from "../mod.ts";

test("validateImageDimensions - valid dimensions", () => {
    validateImageDimensions(100, 100);
    validateImageDimensions(1, 1);
    validateImageDimensions(MAX_IMAGE_DIMENSION, MAX_IMAGE_DIMENSION);
});

test("validateImageDimensions - invalid dimensions", () => {
    assertThrows(() => validateImageDimensions(0, 100));
    assertThrows(() => validateImageDimensions(100, 0));
    assertThrows(() => validateImageDimensions(-1, 100));
    assertThrows(() => validateImageDimensions(100, -1));
    assertThrows(() => validateImageDimensions(1.5, 100));
    assertThrows(() => validateImageDimensions(100, 1.5));
});

test("validateImageDimensions - too large", () => {
    assertThrows(() => validateImageDimensions(MAX_IMAGE_DIMENSION + 1, 100));
    assertThrows(() => validateImageDimensions(100, MAX_IMAGE_DIMENSION + 1));
});

test("sanitizeFilename - removes path separators", () => {
    // sanitizeFilename removes path separators and returns just the filename
    const result1 = sanitizeFilename("../../file.png");
    assert(result1.includes("file"), "Should contain 'file'");
    assertEquals(sanitizeFilename("../../file.png"), "file.png");
});

test("sanitizeFilename - preserves valid filenames", () => {
    assertEquals(sanitizeFilename("image.png"), "image.png");
    assertEquals(sanitizeFilename("../../my-image_123.jpg"), "my-image_123.jpg");
});

test("validateFileSize - valid sizes", () => {
    validateFileSize(100, 1000);
    validateFileSize(1, 1000);
    validateFileSize(MAX_EMBED_FILE_SIZE, MAX_EMBED_FILE_SIZE);
});

test("validateFileSize - invalid sizes", () => {
    assertThrows(() => validateFileSize(0, 1000));
    assertThrows(() => validateFileSize(-1, 1000));
    assertThrows(() => validateFileSize(1001, 1000));
});

test("xorEncrypt and xorDecrypt - round trip", () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const password = "mypassword";

    const encrypted = xorEncrypt(data, password);
    const decrypted = xorDecrypt(encrypted, password);

    assertEquals(decrypted, data);
});

test("xorEncrypt - different passwords produce different output", () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);

    const encrypted1 = xorEncrypt(data, "password1");
    const encrypted2 = xorEncrypt(data, "different");

    assert(encrypted1.some((byte, i) => byte !== encrypted2[i]), "Different passwords should produce different output");
});

test("detectImageFormat - PNG", () => {
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A
    const pngData = new Uint8Array([
        0x89,
        0x50,
        0x4E,
        0x47,
        0x0D,
        0x0A,
        0x1A,
        0x0A,
        ...new Array(100).fill(0),
    ]);

    assertEquals(detectImageFormat(pngData), "png");
});

test("detectImageFormat - JPEG", () => {
    // JPEG signature: FF D8 FF
    const jpegData = new Uint8Array([0xFF, 0xD8, 0xFF, ...new Array(100).fill(0)]);

    assertEquals(detectImageFormat(jpegData), "jpeg");
});

test("isLossyFormat - identifies lossy formats", () => {
    assertEquals(isLossyFormat("jpeg"), true);
    assertEquals(isLossyFormat("jpg"), true);
    assertEquals(isLossyFormat("png"), false);
    assertEquals(isLossyFormat("webp"), true); // WebP is treated as lossy by default
    assertEquals(isLossyFormat(null), false);
});

test("getRecommendedOutputFormat - recommends lossless for lossless input", () => {
    const result = getRecommendedOutputFormat("png");
    assertEquals(result.format, "png");
    assert(result.reason.includes("preserves hidden data"));
});

test("getRecommendedOutputFormat - recommends PNG for JPEG input", () => {
    const result = getRecommendedOutputFormat("jpeg");
    assertEquals(result.format, "png");
    assert(result.reason.includes("lossy"));
});
