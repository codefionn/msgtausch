{
  description = "msgtausch Rust forward proxy";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        version = let value = builtins.getEnv "VERSION"; in
          if value == "" then "dev" else value;
        msgtausch = pkgs.rustPlatform.buildRustPackage {
          pname = "msgtausch";
          inherit version;
          src = pkgs.lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "--package" "msgtausch-cli" ];
          cargoTestFlags = [ "--workspace" ];
          nativeBuildInputs = [ pkgs.pkg-config pkgs.protobuf ];
          doCheck = true;
          preBuild = ''
            export MSGTAUSCH_VERSION=${version}
          '';
        };
      in {
        packages.default = msgtausch;
        packages.msgtausch = msgtausch;
        packages.test = msgtausch;

        devShells.default = pkgs.mkShell {
          inputsFrom = [ msgtausch ];
          packages = [
            pkgs.cargo
            pkgs.clippy
            pkgs.rustc
            pkgs.rustfmt
            pkgs.rust-analyzer
            pkgs.docker_29
          ];
          shellHook = ''
            export MSGTAUSCH_VERSION=${version}
            echo "msgtausch dev shell: Rust $(rustc --version) | VERSION=$MSGTAUSCH_VERSION"
          '';
        };
      }) // {
        overlays.default = final: prev: {
          msgtausch = self.packages.${prev.system}.msgtausch;
        };
      };
}
