{ rustPlatform
}:

rustPlatform.buildRustPackage {
  name = "tunnelbore";
  src = ./.;
  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  #nativeBuildInputs = [ clang_14 pkg-config rustfmt ];
  #buildInputs = [ elfutils libbpf zlib ];

  buildType = "debug";
  #RUST_BACKTRACE = 1;
}
