# @pinta365/steganography

A steganography library supporting image and text steganography.

## Features

- **Image Steganography**
  - LSB (Least Significant Bit) embedding for lossless formats
  - JPEG DCT coefficient-domain embedding
  - File embedding with metadata support

- **Text Steganography**
  - Zero-Width Character (ZWC) encoding
  - Optional AES-256-CTR encryption
  - Compression support

## Installation

### Deno / JSR

```bash
deno add jsr:@pinta365/steganography
```

Or import directly:

```typescript
import { decodeText, encodeText } from "jsr:@pinta365/steganography@0.1.0";
```

**Note**: This library is runtime-agnostic and works on Deno, Node.js (18+), Bun, and browsers.

## Usage

### Text Steganography

```typescript
import { decodeText, encodeText } from "@pinta365/steganography";

// Hide text in text
const coverText = "# Project README\n\nInstallation guide...";
const secret = "API key: sk_live_1234567890";
const stegaText = await encodeText(coverText, secret, "password", true);
const { visibleText, secretMessage } = await decodeText(stegaText, "password");
```

### Image Steganography

```typescript
import { createImage, decodeImage, embedTextInImage, encodeImage, extractTextFromImage } from "@pinta365/steganography";

// Load image
const imageData = await Deno.readFile("image.png");
const image = await decodeImage(imageData);

// Embed message
const message = "Hidden secret message";
const modifiedData = embedTextInImage(image.data, message);

// Save image with hidden data
const stegaImage = createImage(image.width, image.height, modifiedData);
const output = await encodeImage(stegaImage, "png");
await Deno.writeFile("stega.png", output);

// Extract message
const loadedImage = await decodeImage(await Deno.readFile("stega.png"));
const extractedMessage = extractTextFromImage(loadedImage.data);
console.log(extractedMessage); // "Hidden secret message"
```

## API Reference

### Types

#### `StegaText`

Branded type for steganographic text containing hidden ZWC data. Returned by encoding functions and accepted by decoding functions for type safety.

```typescript
type StegaText = string & { readonly __brand: "StegaText" };
```

#### `Image`

Image type from @cross/image, re-exported for convenience. Use for type annotations when working with image helper functions.

```typescript
import { decodeImage, Image } from "@pinta365/steganography";

const image: Image = await decodeImage(imageData);
```

### Text Steganography

#### `encodeText(coverText, secretMessage, password?, distribute?)`

Encodes a secret text message into cover text using zero-width characters.

- **coverText** (`string`): Visible text that will contain the hidden message
- **secretMessage** (`string`): Secret text to hide
- **password** (`string?`): Optional password for AES-256-CTR encryption
- **distribute** (`boolean?`): If `true`, distributes ZWC characters throughout text (default: `false`)
- **Returns**: `Promise<StegaText>` - Cover text with invisible ZWC payload embedded

#### `decodeText(stegaText, password?)`

Decodes a hidden text message from text with hidden data.

- **stegaText** (`string | StegaText`): Text containing hidden ZWC data
- **password** (`string?`): Password if the message was encrypted
- **Returns**: `Promise<{ visibleText: string; secretMessage: string | null }>`

#### `encodeBinary(coverText, binaryData, password?, distribute?)`

Encodes binary data (images, files) into cover text using zero-width characters.

- **coverText** (`string`): Visible text that will contain the hidden data
- **binaryData** (`Uint8Array`): Binary data to hide
- **password** (`string?`): Optional password for AES-256-CTR encryption
- **distribute** (`boolean?`): If `true`, distributes ZWC characters throughout text (default: `false`)
- **Returns**: `Promise<StegaText>` - Cover text with invisible ZWC payload embedded

#### `decodeBinary(stegaText, password?)`

Decodes binary data from text with hidden data.

- **stegaText** (`string | StegaText`): Text containing hidden ZWC data
- **password** (`string?`): Password if the data was encrypted
- **Returns**: `Promise<{ visibleText: string; binaryData: Uint8Array | null }>`

#### `decode(stegaText, password?)`

Unified decode function that auto-detects payload type (text or binary).

- **stegaText** (`string | StegaText`): Text containing hidden ZWC data
- **password** (`string?`): Password if the data was encrypted
- **Returns**: `Promise<{ visibleText: string; payloadType: "text" | "binary" | null; textData: string | null; binaryData: Uint8Array | null }>`

#### `hasHiddenData(text)`

Checks if text contains hidden ZWC steganography data.

- **text** (`string | StegaText`): Text to check
- **Returns**: `boolean`

#### `analyzeZWC(text)`

Returns statistics about hidden data in text.

- **text** (`string`): Text to analyze
- **Returns**: `ZWCStats` - Object with `hasHiddenData`, `visibleLength`, `zwcCount`, `estimatedPayloadBytes`, `breakdown`

#### `stripZWC(text)`

Removes all ZWC characters from text (removes any hidden data).

- **text** (`string`): Text to clean
- **Returns**: `string`

### Image Utilities

#### `decodeImage(imageData)`

Decodes image file data into an Image object.

- **imageData** (`Uint8Array`): Image file data (PNG, JPEG, WebP, etc.)
- **Returns**: `Promise<Image>` - Image object with width, height, and RGBA data

#### `encodeImage(image, format, options?)`

Encodes an Image object to file data.

- **image** (`Image`): Image object
- **format** (`string`): Output format (png, jpeg, webp, etc.)
- **options** (`unknown?`): Optional encoding options (format-specific). See [@cross/image documentation](https://cross-image.56k.guru/) for
  format-specific option types:
  - PNG/APNG: `PNGEncoderOptions` (compressionLevel: 0-9, default: 6)
  - WebP: `WebPEncoderOptions` (quality: 1-100, lossless: boolean, default: quality: 90)
  - TIFF: `TIFFEncoderOptions` (compression: "none" | "lzw" | "packbits" | "deflate", default: "lzw")
  - Other formats: See @cross/image types
- **Returns**: `Promise<Uint8Array>` - Encoded image file data

#### `createImage(width, height, data)`

Creates a new Image object.

- **width** (`number`): Image width in pixels
- **height** (`number`): Image height in pixels
- **data** (`Uint8Array`): RGBA image data
- **Returns**: `Image` - Image object

### Image Steganography (LSB)

LSB (Least Significant Bit) steganography embeds data in the least significant bits of image pixels. Works with lossless formats (PNG, WebP lossless,
BMP, etc.). Lossy formats (JPEG) will destroy hidden data on re-encoding.

#### `embedTextInImage(imageData, message, bitDepth?)`

Embeds a text message into image data using LSB (Least Significant Bit).

- **imageData** (`Uint8Array`): RGBA image data
- **message** (`string`): Text message to embed
- **bitDepth** (`number?`): Bits per pixel (1-4, default: `1`)
- **Returns**: `Uint8Array` - Modified image data

#### `extractTextFromImage(imageData, bitDepth?)`

Extracts a text message from image data using LSB. The message length is automatically read from the embedded header.

- **imageData** (`Uint8Array`): RGBA image data
- **bitDepth** (`number?`): Bits per pixel (1-4, default: `1`)
- **Returns**: `string` - Extracted text message

#### `embedDataInImage(imageData, data, bitDepth?)`

Embeds binary data into image data using LSB.

- **imageData** (`Uint8Array`): RGBA image data
- **data** (`Uint8Array`): Binary data to embed
- **bitDepth** (`number?`): Bits per pixel (1-4, default: `1`)
- **Returns**: `Uint8Array` - Modified image data

#### `extractDataFromImage(imageData, dataLength, bitDepth?)`

Extracts binary data from image data using LSB.

- **imageData** (`Uint8Array`): RGBA image data
- **dataLength** (`number`): Length of the data in bytes
- **bitDepth** (`number?`): Bits per pixel (1-4, default: `1`)
- **Returns**: `Uint8Array` - Extracted binary data

#### `embedLSB(imageData, messageBits, bitDepth?)`

Low-level function to embed bits into image pixels.

- **imageData** (`Uint8Array`): RGBA image data
- **messageBits** (`Uint8Array`): Bits to embed
- **bitDepth** (`number?`): Bits per pixel (1-4, default: `1`)
- **Returns**: `Uint8Array` - Modified image data

#### `extractLSB(imageData, bitCount, bitDepth?)`

Low-level function to extract bits from image pixels.

- **imageData** (`Uint8Array`): RGBA image data
- **bitCount** (`number`): Number of bits to extract
- **bitDepth** (`number?`): Bits per pixel (1-4, default: `1`)
- **Returns**: `Uint8Array` - Extracted bits

#### `calculateBitCapacity(width, height, bitDepth?)`

Calculates the bit capacity of an image.

- **width** (`number`): Image width in pixels
- **height** (`number`): Image height in pixels
- **bitDepth** (`number?`): Bits per pixel (1-4, default: `1`)
- **Returns**: `number` - Number of bytes that can be hidden

#### `generateLSBStats(imageData, originalData?)`

Generates LSB statistics for display.

- **imageData** (`Uint8Array`): RGBA image data
- **originalData** (`Uint8Array?`): Original image data for comparison
- **Returns**: Object with LSB statistics per channel (red, green, blue, total)

### JPEG Coefficient Steganography

#### `embedDataInJpegCoefficients(coefficients, data, useChroma?)`

Embeds binary data into JPEG coefficients using DCT coefficient-domain embedding.

- **coefficients** (`JPEGQuantizedCoefficients`): JPEG quantized coefficients (will be modified)
- **data** (`Uint8Array`): Binary data to embed
- **useChroma** (`boolean?`): Use chroma components (default: `true`)
- **Returns**: `JPEGQuantizedCoefficients` - Modified coefficients

#### `extractDataFromJpegCoefficients(coefficients, maxBytes, useChroma?)`

Extracts binary data from JPEG coefficients.

- **coefficients** (`JPEGQuantizedCoefficients`): JPEG quantized coefficients
- **maxBytes** (`number`): Maximum number of bytes to extract
- **useChroma** (`boolean?`): Extract from chroma components (default: `true`)
- **Returns**: `Uint8Array` - Extracted binary data

#### `embedInCoefficients(coefficients, messageBits, useChroma?)`

Low-level function to embed bits into JPEG coefficients.

- **coefficients** (`JPEGQuantizedCoefficients`): JPEG quantized coefficients (will be modified)
- **messageBits** (`Uint8Array`): Bits to embed
- **useChroma** (`boolean?`): Use chroma components (default: `true`)
- **Returns**: `JPEGQuantizedCoefficients` - Modified coefficients

#### `extractFromCoefficients(coefficients, bitCount, useChroma?)`

Low-level function to extract bits from JPEG coefficients.

- **coefficients** (`JPEGQuantizedCoefficients`): JPEG quantized coefficients
- **bitCount** (`number`): Number of bits to extract
- **useChroma** (`boolean?`): Extract from chroma components (default: `true`)
- **Returns**: `Uint8Array` - Extracted bits

#### `calculateJpegCoefficientCapacity(coefficients, useChroma?)`

Calculates the embedding capacity of JPEG coefficients.

- **coefficients** (`JPEGQuantizedCoefficients`): JPEG quantized coefficients
- **useChroma** (`boolean?`): Include chroma components (default: `true`)
- **Returns**: `number` - Number of bytes that can be hidden

#### `extractJpegCoefficients(jpegData)`

Extracts JPEG quantized coefficients from JPEG data.

- **jpegData** (`Uint8Array`): JPEG file data
- **Returns**: `Promise<JPEGQuantizedCoefficients | null>`

#### `encodeJpegFromCoefficients(coefficients)`

Encodes JPEG from quantized coefficients.

- **coefficients** (`JPEGQuantizedCoefficients`): JPEG quantized coefficients
- **Returns**: `Promise<Uint8Array>` - JPEG file data

#### `cloneJpegCoefficients(coefficients)`

Deep clones JPEG coefficients to avoid modifying the original.

- **coefficients** (`JPEGQuantizedCoefficients`): JPEG quantized coefficients
- **Returns**: `JPEGQuantizedCoefficients` - Cloned coefficients

### Utility Functions

#### `bytesToBits(bytes)`

Converts a byte array to a bit array (LSB first).

- **bytes** (`Uint8Array`): Bytes to convert
- **Returns**: `Uint8Array` - Bit array

#### `bitsToBytes(bits)`

Converts a bit array back to bytes (LSB first).

- **bits** (`Uint8Array`): Bits to convert
- **Returns**: `Uint8Array` - Byte array

#### `xorEncrypt(data, password)`

XOR encrypts data using a cyclic password key.

- **data** (`Uint8Array`): Data to encrypt
- **password** (`string`): Password key
- **Returns**: `Uint8Array` - Encrypted data

#### `xorDecrypt(data, password)`

XOR decrypts data (XOR is its own inverse).

- **data** (`Uint8Array`): Data to decrypt
- **password** (`string`): Password key
- **Returns**: `Uint8Array` - Decrypted data

#### `detectImageFormat(data)`

Detects image format from file data.

- **data** (`Uint8Array`): Image file data
- **Returns**: `string | null` - Format name or null if unknown

#### `isLossyFormat(format)`

Checks if a format is lossy (will destroy pixel-domain embedding data on re-encoding).

- **format** (`string | null`): Format name
- **Returns**: `boolean`

#### `getRecommendedOutputFormat(inputFormat)`

Gets a recommended output format based on input format.

- **inputFormat** (`string | null`): Input format name
- **Returns**: Object with `format`, `reason`, and optional `useWebP`

## License

MIT
