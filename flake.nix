{
  description = "msgtausch: Go proxy with Docker/Nix support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
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
      buildTemplPkg = { pkgs }: pkgs.buildGo125Module {
        pname = "templ";
        version = "0.3.1020";
        src = pkgs.fetchFromGitHub {
          owner = "a-h";
          repo = "templ";
          rev = "v0.3.1020";
          hash = "sha256-wv7qKZfnavz8lxfaOaIJJySNsXsjke1ADJuv2kgQOHE=";
        };
        vendorHash = "sha256-i4uDGZb3VZUvIyO2Tt53VR1Do/3OYtj6JccGoFnnlbs=";
        subPackages = [ "cmd/templ" ];
        go = pkgs.go_1_25;
      };

      # Shared msgtausch package definition
      buildMsgtauschPkg = {
        pkgs,
        version ? "dev",
        src ? pkgs.lib.cleanSource ./.,
        doCheck ? false,
      }:
        let
          customTempl = buildTemplPkg { inherit pkgs; };
        in
        pkgs.buildGo125Module {
          pname = "msgtausch";
          inherit version src;
          go = pkgs.go_1_25;
          goVersion = "1.25";
          # Let the builder vendor dependencies internally, but ignore any in-tree vendor/
          vendorHash = "sha256-mhgoBF9q0QFE9M3funQygmmiTa2nBqP6qfO4SOWmoOo=";
          stripVendor = true;
          subPackages = [ "." ];
          env.CGO_ENABLED = 1;
          nativeBuildInputs = [ pkgs.installShellFiles pkgs.git customTempl ];
          ldflags = [
            "-X main.version=${version} -s -w"
          ];
          inherit doCheck;
          checkPhase = pkgs.lib.optionalString doCheck ''
            runHook preCheck
            go test ./...
            runHook postCheck
          '';
          outputs = [ "out" ];
          preBuild = ''
            # Generate templates using the pinned templ package
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
        gopkgs = pkgs.go_1_25;
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
            pkgs.docker_29
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
        packages.test = buildMsgtauschPkg {
          inherit pkgs src;
          version = "test";
          doCheck = true;
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
