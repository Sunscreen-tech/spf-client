{
  description =
    "SPF Client - Rust CLI and TypeScript/WASM library for Sunscreen's Secure Processing Framework";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    crane.url = "github:ipetkov/crane";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, crane, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
          config.allowUnfree = true;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" ];
          targets = [
            "wasm32-unknown-unknown"
            "x86_64-unknown-linux-musl"
            "aarch64-unknown-linux-musl"
          ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common arguments for all Rust builds
        commonArgs = {
          src = craneLib.cleanCargoSource (craneLib.path ./.);

          strictDeps = true;

          buildInputs = [
            # No system dependencies needed - using rustls instead of OpenSSL
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            # macOS-specific dependencies
            pkgs.libiconv
          ];

          nativeBuildInputs = [ pkgs.pkg-config ];
        };

        # Build dependencies only (for caching)
        # On Linux, build dependencies for musl target to match CLI build
        muslTarget = if pkgs.stdenv.hostPlatform.isAarch64 then
          "aarch64-unknown-linux-musl"
        else
          "x86_64-unknown-linux-musl";

        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          pname = "spf_client-deps";
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          # Use musl target on Linux for static binaries (rustflags in .cargo/config.toml)
          CARGO_BUILD_TARGET = muslTarget;
        });

        # Individual crate-level build artifacts
        individualCrateArgs = commonArgs // {
          inherit cargoArtifacts;
          inherit (craneLib.crateNameFromCargoToml {
            inherit (commonArgs) src;
          })
            version;
        };

        # TypeScript npm dependencies hash (shared between package and checks)
        typescriptNpmDepsHash =
          pkgs.lib.fakeHash;

        # Build the Rust library + CLI (native target, no WASM)
        # On Linux, build with musl for fully static binaries (rustflags in .cargo/config.toml)
        spf-cli-unwrapped = craneLib.buildPackage (individualCrateArgs // {
          pname = "spf_client";
          cargoExtraArgs = "--bin spf-client";
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          # Use musl target on Linux for portable static binaries
          CARGO_BUILD_TARGET = muslTarget;
        });

        # Portable macOS binary for distribution (rewrites libiconv to system path)
        spf-cli-darwin-portable = pkgs.stdenv.mkDerivation {
          pname = "spf-client-darwin-portable";
          inherit (individualCrateArgs) version;

          buildInputs =
            pkgs.lib.optionals pkgs.stdenv.isDarwin [ pkgs.darwin.cctools ];

          unpackPhase = "true";

          installPhase = ''
            mkdir -p $out/bin
            cp ${spf-cli-unwrapped}/bin/spf-client $out/bin/
          '';

          postFixup = pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
            # Find the current libiconv path from the Nix store
            OLD_LIBICONV=$(otool -L $out/bin/spf-client | grep libiconv | awk '{print $1}' | grep /nix/store || true)

            if [ -n "$OLD_LIBICONV" ]; then
              install_name_tool -change \
                "$OLD_LIBICONV" \
                /usr/lib/libiconv.2.dylib \
                $out/bin/spf-client
            fi
          '';
        };

        # Build WASM bindings using crane
        spf-wasm-crate = craneLib.buildPackage (individualCrateArgs // {
          pname = "spf_client_wasm";
          cargoExtraArgs = "--lib --target wasm32-unknown-unknown";

          CARGO_BUILD_TARGET = "wasm32-unknown-unknown";

          # Don't run tests for WASM target
          doCheck = false;
        });

        # Generate JavaScript bindings from WASM
        spf-wasm = pkgs.stdenv.mkDerivation {
          pname = "spf-wasm-bindings";
          inherit (individualCrateArgs) version;

          nativeBuildInputs = [ pkgs.wasm-bindgen-cli pkgs.binaryen ];

          # Use the WASM file built by crane
          src = spf-wasm-crate;

          buildPhase = ''
            # Find the WASM file
            WASM_FILE=$(find . -name "spf_client.wasm" -type f | head -1)

            if [ -z "$WASM_FILE" ]; then
              echo "Error: Could not find spf_client.wasm"
              find . -name "*.wasm"
              exit 1
            fi

            echo "Found WASM file: $WASM_FILE"

            # Generate bindings
            mkdir -p wasm-bindings
            wasm-bindgen "$WASM_FILE" \
              --out-dir wasm-bindings \
              --typescript \
              --target bundler \
              --weak-refs

            # Optimize WASM with wasm-opt (aggressive size optimization)
            wasm-opt wasm-bindings/*.wasm -Oz -o wasm-bindings/spf_client_bg.wasm.opt
            mv wasm-bindings/spf_client_bg.wasm.opt wasm-bindings/spf_client_bg.wasm
          '';

          installPhase = ''
            mkdir -p $out
            cp -r wasm-bindings $out/
          '';
        };

        # TypeScript package with WASM bindings
        spf-typescript = pkgs.buildNpmPackage {
          pname = "spf-client-typescript";
          inherit (individualCrateArgs) version;

          src = ./typescript;

          npmDepsHash = typescriptNpmDepsHash;

          # Copy WASM bindings early so they're available for TypeScript compilation
          postPatch = ''
            # WASM bindings need to be at the root (same level as src/)
            cp -r ${spf-wasm}/wasm-bindings .
            ls -la wasm-bindings/
          '';

          buildPhase = ''
            npm run build:ts
          '';

          installPhase = ''
            mkdir -p $out
            cp -r dist $out/
            cp -r wasm-bindings $out/
            cp package.json $out/
            cp README.md $out/ || true
          '';
        };

        # TypeScript package as tarball for distribution
        spf-typescript-tarball = pkgs.runCommand
          "sunscreen-spf-client-${individualCrateArgs.version}.tgz" {
            buildInputs = [ pkgs.nodejs ];
          } ''
            # Set HOME for npm
            export HOME=$TMPDIR

            # Copy package contents to temp directory
            mkdir -p package
            cp -r ${spf-typescript}/dist package/
            cp -r ${spf-typescript}/wasm-bindings package/
            cp ${spf-typescript}/package.json package/

            # Create npm-compatible tarball
            cd package
            npm pack --pack-destination=$PWD
            mv *.tgz $out
          '';

        # Integration tests runner script (requires SPF server)
        rust-integration-tests =
          pkgs.writeShellScriptBin "spf-integration-tests" ''
            set -e

            # Default to localhost if not set
            export SPF_ENDPOINT=''${SPF_ENDPOINT:-http://localhost:8080}

            echo "Running Rust integration tests against $SPF_ENDPOINT..."
            echo "Note: This will compile tests from your local checkout"
            echo ""

            # Find the spf-client directory (assuming we're running from it or a subdirectory)
            if [ -f "Cargo.toml" ] && grep -q "name = \"spf_client\"" Cargo.toml 2>/dev/null; then
              PROJECT_DIR="$PWD"
            else
              echo "Error: Please run this from the spf-client project directory"
              echo "Current directory: $PWD"
              exit 1
            fi

            cd "$PROJECT_DIR"
            ${rustToolchain}/bin/cargo test --features integration-tests "$@"
          '';

        # TypeScript integration tests runner script (requires TEST_ENDPOINT)
        typescript-integration-tests =
          pkgs.writeShellScriptBin "spf-typescript-tests" ''
            set -e

            if [ -z "$TEST_ENDPOINT" ]; then
              echo "ERROR: TEST_ENDPOINT environment variable must be set"
              echo "Example: TEST_ENDPOINT=https://spf.sunscreen.tech nix run .#typescript-tests"
              exit 1
            fi

            echo "Running TypeScript tests against $TEST_ENDPOINT..."

            # Create temp directory for test run
            TESTDIR=$(mktemp -d)
            trap "chmod -R +w $TESTDIR && rm -rf $TESTDIR" EXIT

            # Copy source to temp directory
            cp -r ${./typescript}/* $TESTDIR/
            chmod -R +w $TESTDIR
            cd $TESTDIR

            # Copy WASM bindings
            cp -r ${spf-wasm}/wasm-bindings .
            chmod -R +w wasm-bindings

            # Install dependencies, build TypeScript, and run tests
            export HOME=$TESTDIR
            ${pkgs.nodejs}/bin/npm install --silent
            ${pkgs.nodejs}/bin/npm run build:ts
            ${pkgs.nodejs}/bin/npm test
          '';

        # Sunscreen LLVM (only for dev shell)
        sunscreen-llvm = pkgs.callPackage ./sunscreen-llvm.nix { };

        # Publish TypeScript package to npm
        publish-typescript = pkgs.writeShellScriptBin "publish-typescript" ''
          echo "Building TypeScript tarball with Nix..."
          TARBALL=$(${pkgs.nix}/bin/nix build .#spf-typescript-tarball --no-link --print-out-paths)
          echo "Publishing $TARBALL to npm..."
          echo "npm will prompt for OTP if required"
          ${pkgs.nodejs}/bin/npm publish "$TARBALL" --access public
        '';

      in {
        packages = {
          # Default package - the CLI
          default = spf-cli-unwrapped;

          spf-cli = spf-cli-unwrapped;
          spf-wasm = spf-wasm;
          spf-typescript = spf-typescript;
          spf-typescript-tarball = spf-typescript-tarball;

          # Test runners (for integration testing)
          rust-integration-tests = rust-integration-tests;
          typescript-integration-tests = typescript-integration-tests;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
          # Portable macOS binary for distribution (Darwin only)
          spf-cli-portable = spf-cli-darwin-portable;
        };

        apps = {
          # Default app - run the CLI
          default = {
            type = "app";
            program = "${spf-cli-unwrapped}/bin/spf-client";
          };

          # Rust integration tests (requires SPF server)
          rust-integration-tests = {
            type = "app";
            program = "${rust-integration-tests}/bin/spf-integration-tests";
          };

          # TypeScript tests (requires TEST_ENDPOINT)
          typescript-tests = {
            type = "app";
            program =
              "${typescript-integration-tests}/bin/spf-typescript-tests";
          };
        };

        checks = {
          # Run unit tests (no integration-tests feature)
          rust-unit-tests = craneLib.cargoTest (individualCrateArgs // {
            cargoTestExtraArgs = "--lib --bins";
            CARGO_BUILD_FEATURES = "";
          });

          # Run clippy
          cargo-clippy = craneLib.cargoClippy (individualCrateArgs // {
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          # Check formatting
          cargo-fmt-check = craneLib.cargoFmt { inherit (commonArgs) src; };

          # TypeScript type checking (no test running, no network)
          typescript-typecheck = pkgs.buildNpmPackage {
            pname = "spf-typescript-typecheck";
            inherit (individualCrateArgs) version;

            src = ./typescript;

            npmDepsHash = typescriptNpmDepsHash;

            postPatch = ''
              cp -r ${spf-wasm}/wasm-bindings .
            '';

            buildPhase = ''
              npm run typecheck
            '';

            installPhase = ''
              touch $out
            '';

            dontNpmBuild = true;
          };

          # Verify packages build
          packages-build = pkgs.runCommand "packages-build" { } ''
            echo "Verifying all packages build successfully..."

            test -f ${spf-cli-unwrapped}/bin/spf-client || exit 1
            test -d ${spf-wasm}/wasm-bindings || exit 1
            test -d ${spf-typescript}/dist || exit 1

            echo "All packages built successfully!"
            touch $out
          '';
        };

        devShells.default = pkgs.mkShellNoCC {
          packages = with pkgs; [
            # Sunscreen LLVM (for FHE program development)
            sunscreen-llvm

            # WASM tools
            wasm-pack
            wasm-bindgen-cli

            # Node.js and TypeScript
            nodejs
            nodePackages.typescript
            nodePackages.typescript-language-server

            # Build tools
            pkg-config

            # Infrastructure
            terraform

            # Useful utilities
            jq

            # Publishing helper
            publish-typescript
          ];

          shellHook = ''
            # Add scripts directory to PATH
            export PATH="$PWD/scripts:$PATH"

            echo "SPF Client development environment loaded"
            echo ""
            echo "Available commands:"
            echo "  cargo build --bin spf-client             - Build Rust CLI"
            echo "  cargo test                               - Run unit tests"
            echo "  cargo test --features integration-tests  - Run integration tests"
            echo "  cd typescript && npm run build           - Build TypeScript package"
            echo "  nix build                                - Build CLI via Nix"
            echo "  nix build .#spf-typescript               - Build TypeScript package via Nix"
            echo "  nix flake check                          - Run all checks"
            echo "  publish-typescript                       - Build and publish to npm"
            echo "  clean                                    - Clean all build artifacts"
            echo ""
            echo "Sunscreen LLVM: ${sunscreen-llvm}/bin/clang"
          '';
        };
      });
}
