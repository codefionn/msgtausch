{
  description = "msgtausch: Go proxy with Docker/Nix support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        gopkgs = (import nixpkgs { inherit system; }).go_1_24;
        goVersion = "1.24";
        version =
          let
            v = builtins.getEnv "VERSION";
          in
          if v == "" then "dev" else v;
        src = pkgs.lib.cleanSource ./.;
      in
      {
        packages.msgtausch = pkgs.buildGo124Module {
          pname = "msgtausch";
          inherit version src;
          go = gopkgs;
          goVersion = goVersion;
          vendorHash = "sha256-WQGzZ5o0WNir/fFgzaA8Ng+ssasaxTxlEyNXxuHNRIM="; # set after first build or use 'nix develop' to update
          subPackages = [ "." ];
          CGO_ENABLED = 0;
          ldflags = [
            "-X main.version=${version} -s -w"
          ];
          doCheck = false;
          outputs = [ "out" ];
          postInstall = ''
            mkdir -p $out/bin
            mv $GOPATH/bin/msgtausch $out/bin/
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            gopkgs
            pkgs.docker
            pkgs.git
            pkgs.gnumake
            pkgs.gotools
          ];
          shellHook = ''
            export CGO_ENABLED=0
            export VERSION=${version}
            echo "msgtausch devShell: Go ${gopkgs.version} | VERSION=${version}"
          '';
        };

        # Run tests: nix build .#test
        packages.test = pkgs.stdenv.mkDerivation {
          name = "msgtausch-tests";
          src = src;
          buildInputs = [
            gopkgs
            pkgs.git
          ];
          buildPhase = ''
            ${gopkgs}/bin/go test -v ./...
          '';
          installPhase = ''
            mkdir -p $out
            touch $out/tests-done
          '';
        };
      }
    );
}
