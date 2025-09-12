{
  description = "msgtausch: Go proxy with Docker/Nix support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      # Custom templ package with exact version
      buildTemplPkg = { pkgs }: pkgs.buildGo124Module {
        pname = "templ";
        version = "0.3.906";
        src = pkgs.fetchFromGitHub {
          owner = "a-h";
          repo = "templ";
          rev = "v0.3.906";
          hash = "sha256-Og1FPCEkBnyt1nz45imDiDNZ4CuWSJJPxGYcPzRgBE8=";
        };
        vendorHash = "sha256-oObzlisjvS9LeMYh3DzP+l7rgqBo9bQcbNjKCUJ8rcY=";
        subPackages = [ "cmd/templ" ];
        go = pkgs.go_1_24;
      };

      # Shared msgtausch package definition
      buildMsgtauschPkg = { pkgs, version ? "dev", src ? pkgs.lib.cleanSource ./. }: 
        let
          customTempl = buildTemplPkg { inherit pkgs; };
        in
        pkgs.buildGo124Module {
          pname = "msgtausch";
          inherit version src;
          go = pkgs.go_1_24;
          goVersion = "1.24";
          # Let the builder vendor dependencies internally, but ignore any in-tree vendor/
          vendorHash = "sha256-rFUVAUivUxhDHo/COi5mfX3Mfoqhfma3MuRn48Sxuqg=";
          stripVendor = true;
          subPackages = [ "." ];
          env.CGO_ENABLED = 1;
          nativeBuildInputs = [ pkgs.installShellFiles pkgs.git customTempl ];
          ldflags = [
            "-X main.version=${version} -s -w"
          ];
          doCheck = false;
          outputs = [ "out" ];
          preBuild = ''
            # Generate templates using the nixpkgs templ package
            templ generate
          '';
          postInstall = ''
            mkdir -p $out/bin
            mv $GOPATH/bin/msgtausch $out/bin/
          '';
        };
    in
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
        packages.default = buildMsgtauschPkg { inherit pkgs version src; };
        packages.msgtausch = buildMsgtauschPkg { inherit pkgs version src; };
        packages.templ = buildTemplPkg { inherit pkgs; };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            gopkgs
            pkgs.docker
            pkgs.git
            pkgs.gnumake
            pkgs.gotools
          ];
          shellHook = ''
            export CGO_ENABLED=1
            export GOFLAGS="-mod=mod"
            export VERSION=${version}
            echo "msgtausch devShell: Go ${gopkgs.version} | VERSION=${version} | GOFLAGS=$GOFLAGS"
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
            export GOFLAGS="-mod=mod"
            ${gopkgs}/bin/go test -v ./...
          '';
          installPhase = ''
            mkdir -p $out
            touch $out/tests-done
          '';
        };
      }
    ) // {
      # Define the overlay at the top level
      overlays.default = final: prev: {
        msgtausch = buildMsgtauschPkg {
          pkgs = prev;
          version = let v = builtins.getEnv "VERSION"; in if v == "" then "dev" else v;
          src = prev.lib.cleanSource ./.;
        };
      };
    };
}
