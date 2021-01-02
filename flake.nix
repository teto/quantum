{
  description = "Multipath tcp pcap analyzer tool";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    # temporary until this gets fixed upstream
    poetry.url = "github:teto/poetry2nix/fix_tag";

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, poetry }:
    flake-utils.lib.eachDefaultSystem (system: let
    in rec {

      packages.mptcpanalyzer = nixpkgs.legacyPackages.x86_64-linux.hello;

      defaultPackage = packages.mptcpanalyzer;

    });
}
