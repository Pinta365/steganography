import { test } from "@cross/test";
import { assert, assertEquals, assertNotEquals } from "@std/assert";
import {
    analyzeZWC,
    calculateTextCapacity,
    decode,
    decodeBinary,
    decodeText,
    encodeBinary,
    encodeText,
    hasHiddenData,
    MAX_COVER_LENGTH,
    MAX_SECRET_LENGTH,
    stripZWC,
} from "../mod.ts";

test("encodeText and decodeText - basic functionality", async () => {
    const coverText =
        "This is a longer cover text with enough capacity for a hidden message. It needs to be long enough to provide sufficient space for zero-width characters.";
    const secret = "Hidden message";

    const stegaText = await encodeText(coverText, secret);
    const { visibleText, secretMessage } = await decodeText(stegaText);

    assertEquals(visibleText.trim(), coverText);
    assertEquals(secretMessage, secret);
});

test("encodeText with password", async () => {
    const coverText =
        "This is a much longer cover text with enough capacity for a hidden message. It needs to be long enough to provide sufficient space for zero-width characters. The text should have plenty of room for encoding secret messages with encryption overhead. We need extra space because encryption adds approximately 32 bytes of overhead to the payload size.";
    const secret = "Secret message";
    const password = "mypassword";

    const stegaText = await encodeText(coverText, secret, password);
    const { secretMessage } = await decodeText(stegaText, password);

    assertEquals(secretMessage, secret);
});

test("encodeText with distribute option", async () => {
    const coverText =
        "This is a longer cover text with multiple words and sentences. It needs to be long enough to provide sufficient space for zero-width characters when distributing them throughout the text.";
    const secret = "Hidden";

    const stegaText = await encodeText(coverText, secret, undefined, true);
    const { visibleText, secretMessage } = await decodeText(stegaText);

    assertEquals(visibleText.trim(), coverText);
    assertEquals(secretMessage, secret);
});

test("encodeBinary and decodeBinary", async () => {
    const coverText =
        "This is a longer cover text with enough capacity for binary data. It needs to be long enough to provide sufficient space for zero-width characters.";
    const binaryData = new Uint8Array([1, 2, 3, 4, 5]);

    const stegaText = await encodeBinary(coverText, binaryData);
    const { visibleText, binaryData: extracted } = await decodeBinary(stegaText);

    assertEquals(visibleText.trim(), coverText);
    assertEquals(extracted, binaryData);
});

test("decode - auto-detects payload type", async () => {
    const coverText =
        "This is a longer cover text with enough capacity for hidden data. It needs to be long enough to provide sufficient space for zero-width characters.";

    // Test text payload
    const textStega = await encodeText(coverText, "secret");
    const textResult = await decode(textStega);
    assertEquals(textResult.payloadType, "text");
    assertEquals(textResult.textData, "secret");
    assertEquals(textResult.binaryData, null);

    // Test binary payload
    const binaryData = new Uint8Array([1, 2, 3]);
    const binaryStega = await encodeBinary(coverText, binaryData);
    const binaryResult = await decode(binaryStega);
    assertEquals(binaryResult.payloadType, "binary");
    assertEquals(binaryResult.binaryData, binaryData);
    assertEquals(binaryResult.textData, null);
});

test("hasHiddenData - detects hidden data", () => {
    const plainText = "No hidden data here";
    assertEquals(hasHiddenData(plainText), false);
});

test("hasHiddenData - detects stega text", async () => {
    const coverText =
        "This is a longer cover text with enough capacity for a hidden message. It needs to be long enough to provide sufficient space for zero-width characters.";
    const secret = "Hidden";
    const stegaText = await encodeText(coverText, secret);

    assertEquals(hasHiddenData(stegaText), true);
});

test("stripZWC - removes all ZWC characters", async () => {
    const coverText =
        "This is a longer cover text with enough capacity for a hidden message. It needs to be long enough to provide sufficient space for zero-width characters.";
    const secret = "Hidden";
    const stegaText = await encodeText(coverText, secret);

    const stripped = stripZWC(stegaText);
    assertEquals(stripped, coverText);
});

test("calculateTextCapacity - calculates capacity", () => {
    const shortText = "Short";
    const mediumText = "This is a medium length text with some words and spaces.";
    const longText = "A".repeat(1000);

    const shortCapacity = calculateTextCapacity(shortText);
    const mediumCapacity = calculateTextCapacity(mediumText);
    const longCapacity = calculateTextCapacity(longText);

    assert(longCapacity > mediumCapacity, "Longer text should have more capacity");
    assert(mediumCapacity > shortCapacity, "Medium text should have more capacity than short");
    assert(mediumCapacity > 0, "Medium text should have some capacity");
    // Very short text may have 0 capacity, which is expected
});

test("analyzeZWC - returns statistics", async () => {
    const coverText =
        "This is a longer cover text with enough capacity for a hidden message. It needs to be long enough to provide sufficient space for zero-width characters.";
    const secret = "Hidden message";
    const stegaText = await encodeText(coverText, secret);

    const stats = analyzeZWC(stegaText);

    assertEquals(stats.hasHiddenData, true);
    assertEquals(stats.visibleLength, coverText.length);
    assert(stats.zwcCount > 0, "Should have ZWC characters");
    assert(stats.estimatedPayloadBytes > 0, "Should estimate payload size");
});

test("encodeText - respects maxSecretLength", async () => {
    const coverText =
        "This is a longer cover text with enough capacity for a hidden message. It needs to be long enough to provide sufficient space for zero-width characters.";
    const largeSecret = "A".repeat(MAX_SECRET_LENGTH + 1);

    try {
        await encodeText(coverText, largeSecret);
        assert(false, "Should have thrown error");
    } catch (error) {
        assert(error instanceof Error);
        assert(error.message.includes("Secret message too long"));
    }
});

test("encodeText - respects maxCoverLength", async () => {
    const largeCover = "A".repeat(MAX_COVER_LENGTH + 1);
    const secret = "Secret";

    try {
        await encodeText(largeCover, secret);
        assert(false, "Should have thrown error");
    } catch (error) {
        assert(error instanceof Error);
        assert(error.message.includes("Cover text too long"));
    }
});

test("encodeText - capacity warning with strictCapacity: false", async () => {
    const coverText =
        "This is a longer cover text with enough capacity for a hidden message. It needs to be long enough to provide sufficient space for zero-width characters.";
    const largeSecret = "A".repeat(500);

    // Should warn but not throw if we exceed capacity
    const stegaText = await encodeText(coverText, largeSecret, undefined, false, {
        strictCapacity: false,
        maxPayloadBytes: 100,
    });

    assertNotEquals(stegaText, coverText);
});

test("encodeText - custom maxPayloadBytes", async () => {
    const coverText =
        "This is a longer cover text with enough capacity for a hidden message. It needs to be long enough to provide sufficient space for zero-width characters.";
    const secret = "Secret";

    const stegaText = await encodeText(coverText, secret, undefined, false, {
        maxPayloadBytes: 100,
    });

    const { secretMessage } = await decodeText(stegaText);
    assertEquals(secretMessage, secret);
});
