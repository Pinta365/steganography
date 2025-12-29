# Agents quick checklist

This document provides guidelines for AI agents and contributors working on @pinta365/steganography.

## Project Structure

- **`mod.ts`**: Main entry point, re-exports all public APIs
- **`src/common.ts`**: Common utilities (XOR encryption, bit/byte conversion, validation)
- **`src/image.ts`**: Image steganography (LSB pixel-domain and JPEG DCT coefficient-domain)
- **`src/text.ts`**: Text steganography (Zero-Width Character encoding)
- **`test/`**: Test files using `@cross/test` for cross-runtime testing
  - `common.test.ts`: Tests for common utilities
  - `image.test.ts`: Tests for image steganography
  - `text.test.ts`: Tests for text steganography
- **`local_test/`**: Local testing scripts (gitignored, for development)
- **`references/cross-image-package/`**: Reference copy of `@cross/image` library for looking up implementation details

## Development

### Running Locally

```bash
deno task dev
```

### Pre-push Validation

Run: `deno task prepush`

This runs:

- `deno fmt --check` - Format check
- `deno lint` - Linter
- `deno check mod.ts` - Type checking
- `deno test -A` - Run all tests

**Note**: `deno check` may show type resolution errors for transitive npm dependencies. This is a known Deno limitation and doesn't affect runtime
functionality.

### Testing

```bash
deno test -A
```

Tests use `@cross/test` for cross-runtime compatibility (Deno, Bun, Node.js, browsers).

### Local Testing

For manual testing and experimentation, use files in `local_test/`:

- `local_test/dev.ts`: Example text steganography scenarios
- `local_test/test_image.ts`: Simple image steganography test

These files are gitignored and can be modified freely for development.

## Guidelines

### Code Style

- **TypeScript strict mode** - ensure proper typing
- **4-space indentation**, 150 character line width (see `deno.json`)
- **Runtime-agnostic** - code must work on Deno, Node.js (18+), Bun, and browsers

### Key Conventions

- **Image Processing**: Use `@cross/image` library (via JSR). See `references/cross-image-package/` for implementation details
- **Testing**: Use `@cross/test` for all tests to ensure cross-runtime compatibility
- **Format Handling**:
  - Lossless formats (PNG, WebP lossless, BMP, etc.): Pixel-domain LSB embedding
  - JPEG: Coefficient-domain DCT embedding (survives re-compression)
- **Text Steganography**: Zero-Width Character (ZWC) encoding with optional compression and AES-256-CTR encryption
- **Error Handling**: Provide clear, actionable error messages with context

### Important Notes

- **Lossy Formats**: JPEG is fully supported using DCT coefficient-domain embedding, which allows data to survive JPEG re-compression. Other lossy
  formats may be added in the future.
- **Bit Depth**: Supports 1-4 bits per channel for LSB embedding. Higher bit depth = more capacity but more visible changes.
- **Encryption**:
  - Text steganography: AES-256-CTR with PBKDF2 key derivation (optional)
  - Image steganography: XOR encryption (simple but effective)
- **Capacity Management**: Both text and image functions include capacity checks with configurable limits (`maxPayloadBytes`, `strictCapacity`, etc.)
- **Compression**: Text steganography uses deflate compression with runtime-specific fallbacks (CompressionStream API, Bun zlib, Node.js zlib)

### File Organization

- **Source code**: `src/` directory
- **Tests**: `test/` directory (use `@cross/test`)
- **Local testing**: `local_test/` (gitignored, for development)
- **References**: `references/cross-image-package/` for looking up `@cross/image` implementation details
- **Documentation**: `README.md` for user-facing documentation
- **Changelog**: `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format

### Dependencies

- **@cross/image**: Image processing (via JSR)
- **@cross/test**: Cross-runtime testing framework (via JSR)
- **@std/assert**: Assertion library (via JSR)

### Testing Guidelines

- All tests should use `@cross/test` for cross-runtime compatibility
- Tests should be in `test/` directory with `.test.ts` suffix
- Test files should be named to match their source files (e.g., `test/image.test.ts` for `src/image.ts`)
- Use descriptive test names that explain what is being tested
- For local experimentation, use `local_test/` directory (gitignored)

### API Design

- **Helper Functions**: Provide wrapper functions to reduce direct dependency on `@cross/image` (e.g., `decodeImage`, `encodeImage`, `createImage`)
- **Type Safety**: Use branded types where appropriate (e.g., `StegaText`)
- **Options Objects**: Use optional options objects for configuration (e.g., `EncodeOptions`, `ImageEncodeOptions`)
- **Capacity**: Always validate capacity and provide helpful error messages with suggestions

### Changelog Maintenance

- **CHANGELOG.md**: Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format
- Update the `[Unreleased]` section with changes as they are made
- When releasing a new version:
  1. Move `[Unreleased]` changes to a new version section with date
  2. Add version comparison links at the bottom
  3. Update the `[Unreleased]` link to compare from the new version
- Use standard categories: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`

### Future Work

- **Additional Lossy Formats**: DCT domain steganography for other lossy formats (WebP lossy, etc.)
- Keep this file updated as the project evolves
- Maintain backward compatibility for user-facing features
