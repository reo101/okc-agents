{
  description = "okc-agents for termux (or nix-on-droid)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    naersk.url = "github:nmattia/naersk";
    flake-parts.url = "github:hercules-ci/flake-parts";
    systems.url = "github:nix-systems/default";
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
          cargoToml = lib.pipe ./Cargo.toml [
            builtins.readFile
            builtins.fromTOML
          ];
          packageName = cargoToml.package.name;
          okc-agent = pkgs.callPackage ./. { naersk = pkgs.callPackage inputs.naersk { }; };
        in
        {
          packages.${packageName} = okc-agent;

          packages.default = config.packages.${packageName};

          checks = {
            format =
              pkgs.runCommand "check-format"
                {
                  nativeBuildInputs = with pkgs; [
                    rustfmt
                    cargo
                    nixpkgs-fmt
                  ];
                }
                ''
                  ${lib.getExe' pkgs.rustfmt "cargo-fmt"} fmt --manifest-path ${./.}/Cargo.toml -- --check
                  ${lib.getExe pkgs.nixfmt-rfc-style} --check ${./.}
                  touch $out
                '';
            ${packageName} = config.packages.${packageName};
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [ config.packages.${packageName} ];
            nativeBuildInputs = with pkgs; [
              # Rust
              rustup # for rust-analyzer
              rustfmt

              # Nix
              nil
              nixfmt-rfc-style
            ];
            env.LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          };
        };
    };
}
