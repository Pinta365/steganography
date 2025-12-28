// scripts/build_npm.ts
// deno-lint-ignore no-import-prefix
import { build, emptyDir } from "jsr:@deno/dnt@0.42.3";

import pkg from "../deno.json" with { type: "json" };

const outputDir = "./npm";

await emptyDir(outputDir);

await build({
    importMap: "deno.json",
    entryPoints: ["./mod.ts"],
    outDir: outputDir,
    shims: {
        deno: false,
    },
    package: {
        name: "@pinta365/steganography",
        version: pkg.version,
        description:
            "A steganography library supporting image and text steganography with LSB embedding, JPEG DCT coefficients, and zero-width character encoding.",
        license: "MIT",
        repository: {
            type: "git",
            url: "git+https://github.com/pinta365/steganography.git",
        },
        bugs: {
            url: "https://github.com/pinta365/steganography/issues",
        },
        homepage: "https://github.com/pinta365/steganography",
        keywords: [
            "steganography",
            "stega",
            "hidden-data",
            "data-hiding",
            "lsb",
            "least-significant-bit",
            "image-steganography",
            "text-steganography",
            "zero-width-characters",
            "zwc",
            "jpeg-steganography",
            "dct-coefficients",
            "encryption",
            "aes-256",
            "cross-runtime",
            "deno",
            "node",
            "bun",
            "typescript",
        ],
        engines: {
            node: ">=18.0.0",
        },
    },
    async postBuild() {
        Deno.copyFileSync("LICENSE", "npm/LICENSE");
        Deno.copyFileSync("README.md", "npm/README.md");
        const npmIgnore = "npm/.npmignore";
        const npmIgnoreContent = [
            "*.map",
            "test/",
            "local_test/",
            "scripts/",
            "references/",
            ".github/",
            "AGENTS.md",
        ].join("\n");
        try {
            const content = await Deno.readTextFile(npmIgnore);
            await Deno.writeTextFile(npmIgnore, content + "\n" + npmIgnoreContent);
        } catch {
            await Deno.writeTextFile(npmIgnore, npmIgnoreContent);
        }
    },
    typeCheck: "both",
    test: false,
    compilerOptions: {
        lib: ["ESNext", "DOM", "DOM.Iterable"],
        sourceMap: false,
        inlineSources: false,
    },
});
