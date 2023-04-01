{

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;
  inputs.fenix = {
    url = github:nix-community/fenix;
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.wat = {
    url = github:thelegy/wat;
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, fenix, wat, self}: {

    overlays.default = final: prev: {

      rust_toolchain_nightly = final.fenix.complete;
      rustc_nightly = final.rust_toolchain_nightly.withComponents [ "rustc" "rust-src" ];

      rustPackages_nightly = final.lib.makeScope final.newScope (self: {
        rustPlatform = final.makeRustPlatform { inherit (self) rustc rustc-src cargo; };
        inherit (final.fenix.complete) rustfmt cargo clippy rls;
        rustc = final.fenix.complete.withComponents [ "rustc" "rust-src" ];
    });

      tunnelbore = final.rustPackages.callPackage ./default.nix {};

      tunnelbore_nightly = final.rustPackages_nightly. callPackage ./default.nix {};

    };

    packages = wat.lib.withPkgsForLinux nixpkgs [self.overlays.default fenix.overlay] (pkgs: {
      tunnelbore = pkgs.tunnelbore;
      tunnelbore_nightly = pkgs.tunnelbore_nightly;
      default = pkgs.tunnelbore;
      rust-analyzer = pkgs.rust_toolchain_nightly.rust-analyzer;
    });

    devShells = wat.lib.withPkgsForLinux nixpkgs [self.overlays.default fenix.overlay] (pkgs: rec {
      tunnelbore = pkgs.mkShell {
        inputsFrom = [ pkgs.tunnelbore ];
        packages = [ pkgs.rust-analyzer pkgs.rustfmt ];
      };
      default = tunnelbore;
    });


  };

}
