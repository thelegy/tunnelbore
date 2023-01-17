{

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;
  inputs.wat = {
    url = github:thelegy/wat;
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, wat, self}: {

    overlays.default = final: prev: {

      tunnelbore = final.rustPackages.callPackage ./default.nix {};

    };

    packages = wat.lib.withPkgsForLinux nixpkgs [self.overlays.default] (pkgs: {
      tunnelbore = pkgs.tunnelbore;
      default = pkgs.tunnelbore;
    });

    devShells = wat.lib.withPkgsForLinux nixpkgs [self.overlays.default] (pkgs: rec {
      tunnelbore = pkgs.mkShell {
        inputsFrom = [ pkgs.tunnelbore ];
        packages = [ pkgs.rust-analyzer pkgs.rustfmt ];
      };
      default = tunnelbore;
    });


  };

}
