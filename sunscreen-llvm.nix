{ lib, stdenv, fetchurl, autoPatchelfHook, zlib }:

let
  version = "2025-09-30";
  urlBase =
    "https://github.com/Sunscreen-tech/sunscreen-llvm/releases/download/v${version}";

in stdenv.mkDerivation rec {
  pname = "sunscreen-llvm";
  inherit version;

  src = if stdenv.isDarwin then
    fetchurl {
      url = "${urlBase}/parasol-compiler-macos-aarch64-${version}.tar.gz";
      sha256 = "0ra93mji3j9km7ia21gsqswn49a3abwc1ml1xq643hzq4xigyqjd";
    }
  else if stdenv.isAarch64 then
    fetchurl {
      url = "${urlBase}/parasol-compiler-linux-aarch64-${version}.tar.gz";
      sha256 = "197fybbjvimnyqwwn3q7s9yrljbqp57s42n9znpckmnbcbp8p373";
    }
  else
    fetchurl {
      url = "${urlBase}/parasol-compiler-linux-x86-64-${version}.tar.gz";
      sha256 = "1p0418nqzs6a2smrbqiyrxj34pimm6qzj7k29l4ys226cz6kfz2r";
    };

  nativeBuildInputs = lib.optionals stdenv.isLinux [ autoPatchelfHook ];

  buildInputs = lib.optionals stdenv.isLinux [
    stdenv.cc.cc.lib # Provides libstdc++ and libgcc_s
    zlib
  ];

  # The tarball extracts to current directory, not a subdirectory
  sourceRoot = ".";

  # Don't run configure or build - this is a binary package
  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out
    cp -r * $out/

    runHook postInstall
  '';

  meta = with lib; {
    description =
      "Sunscreen LLVM compiler for parasol target (FHE compilation)";
    homepage = "https://github.com/Sunscreen-tech/sunscreen-llvm";
    license = licenses.agpl3Only;
    platforms = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
    mainProgram = "clang";
  };
}
