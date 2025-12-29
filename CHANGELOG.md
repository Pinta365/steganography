# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2024-12-29

### Fixed

- Fixed GitHub Actions workflow for automated npm publishing
  - Updated npm to version 11.5.1+ (required for OIDC authentication)
  - Properly configured OIDC authentication for npm Trusted Publisher support
  - Streamlined npm publishing process with better error handling

### Changed

- Improved npm publishing workflow reliability and automation

## [0.3.0] - 2024-12-28

### Added

- Animated GIF support with multi-frame embedding modes
  - `"first"` mode: Embed only in the first frame (recommended for most cases)
  - `"all"` mode: Embed the same message in all frames
  - `"split"` mode: Distribute message across frames (useful for large messages)
- Proper frame handling for partial frames, transparency, and disposal methods
- npm package availability - now installable via npm, yarn, pnpm, and bun
- Comprehensive installation instructions for both JSR and npm

### Changed

- Enhanced GIF encoding to properly handle partial frames with correct offsets, dimensions, and transparency
- Improved capacity calculation for multi-frame images
- Updated documentation with installation instructions for all package managers
- Removed Node.js zlib fallback (Node.js 18+ supports CompressionStream natively)

### Fixed

- Fixed GIF encoder to properly handle partial frames with transparency
- Improved frame capacity calculation for multi-frame images
- Enhanced error messages with helpful suggestions

[unreleased]: https://github.com/pinta365/steganography/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/pinta365/steganography/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/pinta365/steganography/compare/v0.2.0...v0.3.0
