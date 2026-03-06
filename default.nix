{
  lib,
  naersk,
  src,
  pkg-config,
  libiconv,
  cargoBuildTarget ? null,
  extraEnv ? { },
  extraNativeBuildInputs ? [ ],
  extraBuildInputs ? [ ],
# , llvmPackages # Optional
# , protobuf     # Optional
}:

naersk.buildPackage (
  {
    inherit src;

    nativeBuildInputs = [
      pkg-config
    ] ++ extraNativeBuildInputs;

    buildInputs = [
      libiconv
    ] ++ extraBuildInputs;

    env = {
      CARGO_BUILD_INCREMENTAL = "false";
      RUST_BACKTRACE = "full";
    } // extraEnv;
    copyLibs = true;

    # Optional: Uncomment if your crate needs libclang for crates like `bindgen`.
    # LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";

    # Optional: Uncomment if your crate needs protobuf.
    # PROTOC = "${protobuf}/bin/protoc";
    # PROTOC_INCLUDE = "${protobuf}/include";

    meta = {
      maintainers = [ "reo101" ];
    };
  }
  // lib.optionalAttrs (cargoBuildTarget != null) {
    CARGO_BUILD_TARGET = cargoBuildTarget;
  }
)
