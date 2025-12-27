import { test } from "@cross/test";
import { assert, assertEquals } from "@std/assert";
import {
    bitsToBytes,
    bytesToBits,
    calculateBitCapacity,
    embedDataInImage,
    embedLSB,
    embedTextInImage,
    extractDataFromImage,
    extractLSB,
    extractTextFromImage,
    MAX_MESSAGE_LENGTH,
} from "../mod.ts";

test("embedTextInImage and extractTextFromImage - basic functionality", () => {
    // Create a simple 10x10 image (white)
    const width = 10;
    const height = 10;
    const imageData = new Uint8Array(width * height * 4);
    imageData.fill(255); // White RGBA

    const message = "Hello";
    const modifiedData = embedTextInImage(imageData, message);
    const extracted = extractTextFromImage(modifiedData);

    assertEquals(extracted, message);
});

test("embedDataInImage and extractDataFromImage", () => {
    const width = 20;
    const height = 20;
    const imageData = new Uint8Array(width * height * 4);
    imageData.fill(255);

    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const modifiedData = embedDataInImage(imageData, data);
    const extracted = extractDataFromImage(modifiedData, data.length);

    assertEquals(extracted, data);
});

test("embedTextInImage - different bit depths", () => {
    const width = 50;
    const height = 50;
    const imageData = new Uint8Array(width * height * 4);
    imageData.fill(255);

    const message = "Test";

    for (let bitDepth = 1; bitDepth <= 4; bitDepth++) {
        const modifiedData = embedTextInImage(imageData, message, bitDepth);
        const extracted = extractTextFromImage(modifiedData, bitDepth);
        assertEquals(extracted, message, `Failed at bitDepth ${bitDepth}`);
    }
});

test("calculateBitCapacity - calculates capacity correctly", () => {
    const width = 100;
    const height = 100;

    const capacity1 = calculateBitCapacity(width, height, 1);
    const capacity2 = calculateBitCapacity(width, height, 2);
    const capacity4 = calculateBitCapacity(width, height, 4);

    assert(capacity2 > capacity1, "bitDepth 2 should have more capacity than 1");
    assert(capacity4 > capacity2, "bitDepth 4 should have more capacity than 2");
    assert(capacity1 > 0, "Should have positive capacity");
});

test("embedTextInImage - respects maxMessageLength", () => {
    const width = 10;
    const height = 10;
    const imageData = new Uint8Array(width * height * 4);
    imageData.fill(255);

    const largeMessage = "A".repeat(MAX_MESSAGE_LENGTH + 1);

    try {
        embedTextInImage(imageData, largeMessage);
        assert(false, "Should have thrown error");
    } catch (error) {
        assert(error instanceof Error);
        assert(error.message.includes("Message too long"));
    }
});

test("embedTextInImage - capacity warning with strictCapacity: false", () => {
    const width = 10;
    const height = 10;
    const imageData = new Uint8Array(width * height * 4);
    imageData.fill(255);

    const capacity = calculateBitCapacity(width, height, 1);
    // Use a message that fits within capacity but is close to the limit
    // Account for the 4-byte header, so we use capacity - 4 bytes
    const messageSize = Math.max(1, capacity - 4);
    const message = "A".repeat(messageSize);

    // Should work without throwing
    const modifiedData = embedTextInImage(imageData, message, 1, {
        strictCapacity: false,
    });

    assert(modifiedData !== imageData, "Data should be modified");

    // Verify we can extract it
    const extracted = extractTextFromImage(modifiedData);
    assertEquals(extracted, message);
});

test("embedTextInImage - custom maxPayloadBytes", () => {
    const width = 100;
    const height = 100;
    const imageData = new Uint8Array(width * height * 4);
    imageData.fill(255);

    const message = "Test message";
    const modifiedData = embedTextInImage(imageData, message, 1, {
        maxPayloadBytes: 50,
    });

    const extracted = extractTextFromImage(modifiedData);
    assertEquals(extracted, message);
});

test("bytesToBits and bitsToBytes - round trip", () => {
    const original = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const bits = bytesToBits(original);
    const back = bitsToBytes(bits);

    assertEquals(back, original);
});

test("embedLSB and extractLSB - round trip", () => {
    const width = 20;
    const height = 20;
    const imageData = new Uint8Array(width * height * 4);
    imageData.fill(255);

    const messageBits = bytesToBits(new Uint8Array([1, 2, 3, 4]));
    const modified = embedLSB(imageData, messageBits, 1);
    const extracted = extractLSB(modified, messageBits.length, 1);
    const back = bitsToBytes(extracted);

    assertEquals(back, new Uint8Array([1, 2, 3, 4]));
});

test("embedLSB - different bit depths", () => {
    const width = 50;
    const height = 50;
    const imageData = new Uint8Array(width * height * 4);
    imageData.fill(255);

    const messageBits = bytesToBits(new Uint8Array([1, 2, 3]));

    for (let bitDepth = 1; bitDepth <= 4; bitDepth++) {
        const modified = embedLSB(imageData, messageBits, bitDepth);
        const extracted = extractLSB(modified, messageBits.length, bitDepth);
        const back = bitsToBytes(extracted);
        assertEquals(back, new Uint8Array([1, 2, 3]), `Failed at bitDepth ${bitDepth}`);
    }
});

test("embedLSB - validates bit depth", () => {
    const imageData = new Uint8Array(100);
    const messageBits = new Uint8Array(10);

    try {
        embedLSB(imageData, messageBits, 0);
        assert(false, "Should have thrown error");
    } catch (error) {
        assert(error instanceof Error);
        assert(error.message.includes("Bit depth"));
    }

    try {
        embedLSB(imageData, messageBits, 5);
        assert(false, "Should have thrown error");
    } catch (error) {
        assert(error instanceof Error);
        assert(error.message.includes("Bit depth"));
    }
});
