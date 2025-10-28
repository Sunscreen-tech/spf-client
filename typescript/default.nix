{ lib, buildNpmPackage, spf-wasm, nix-gitignore }:

let
  # Extract version from package.json to avoid duplication
  packageJson = lib.importJSON ./package.json;
in
buildNpmPackage rec {
  pname = "spf-client-typescript";
  version = packageJson.version;

  # Use nix-gitignore from nixpkgs to respect .gitignore
  src = nix-gitignore.gitignoreSourcePure [ ./.gitignore ] ./.;

  npmDepsHash = "sha256-Rjx1iXEhOFN/FsVIFwZtL4sUM+i4xcdEyU5dLenNd8M=";

  # Copy WASM bindings early so they're available for TypeScript compilation
  postPatch = ''
    # WASM bindings need to be at the root (same level as src/)
    cp -r ${spf-wasm}/wasm-bindings .
  '';

  # Build TypeScript only (WASM bindings provided via spf-wasm parameter)
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

  meta = with lib; {
    description =
      "TypeScript/JavaScript SDK for Sunscreen's Secure Processing Framework (SPF)";
    homepage = "https://github.com/sunscreen-tech/spf-client";
    license = licenses.mit;
    maintainers = [ ];
    platforms = platforms.unix;
  };
}
