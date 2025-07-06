{
  lib,
  naersk,
  pkg-config,
  libiconv,
# , llvmPackages # Optional
# , protobuf     # Optional
}:

naersk.buildPackage {
  src = lib.cleanSource ./.;

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    libiconv
  ];

  env = {
    CARGO_BUILD_INCREMENTAL = "false";
    RUST_BACKTRACE = "full";
  };
  copyLibs = true;

  # Optional: Uncomment if your crate needs libclang for crates like `bindgen`.
  # LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";

  # Optional: Uncomment if your crate needs protobuf.
  # PROTOC = "${protobuf}/bin/protoc";
  # PROTOC_INCLUDE = "${protobuf}/include";

  meta = with lib; {
    maintainers = with maintainers; [ "reo101" ];
  };
}
