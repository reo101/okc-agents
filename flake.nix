{
  description = "okc-agents for termux (or nix-on-droid)";

  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    };
    naersk = {
      url = "github:nmattia/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
    };
    systems = {
      url = "github:nix-systems/default";
    };
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.systems;

      perSystem =
        {
          config,
          pkgs,
          lib,
          ...
        }:
        let
          fs = lib.fileset;
          src = fs.toSource {
            root = ./.;
            fileset = fs.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./src
            ];
          };
          cargoToml = lib.importTOML ./Cargo.toml;
          packageName = cargoToml.package.name;
          mkPackage =
            packageSet: extraArgs:
            packageSet.callPackage ./default.nix ({
              inherit src;
              naersk = packageSet.callPackage inputs.naersk { };
            } // extraArgs);
          okc-agent = mkPackage pkgs { };
        in
        {
          packages = {
            ${packageName} = okc-agent;
            default = config.packages.${packageName};
          };

          checks = {
            format =
              pkgs.runCommand "check-format"
                {
                  nativeBuildInputs = with pkgs; [
                    rustfmt
                    cargo
                    nixfmt-rfc-style
                  ];
                }
                ''
                  ${lib.getExe' pkgs.rustfmt "cargo-fmt"} fmt --manifest-path ${src}/Cargo.toml -- --check
                  ${lib.getExe pkgs.nixfmt-rfc-style} --check ${src}
                  touch $out
                '';
            ${packageName} = config.packages.${packageName};
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [ config.packages.${packageName} ];
            packages = with pkgs; [
              cargo
              clippy
              rust-analyzer
              rustc
              rustfmt
              nil
              nixfmt-rfc-style
            ];
          };
        };
    };
}
