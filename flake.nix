{
  description = "Multipath tcp pcap analyzer tool";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    replica.url = "github:teto/REPLica/nix";

    # temporary until this gets fixed upstream
    # poetry.url = "github:teto/poetry2nix/fix_tag";

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, poetry, replica }@inputs:
    flake-utils.lib.eachDefaultSystem (system: let

      compilerName = "ghc8104";
      pkgs = nixpkgs.legacyPackages."${system}";

      myHaskellPackages = pkgs.haskell.packages."${compilerName}";

      hsEnv = myHaskellPackages.ghcWithPackages(hs: [
        # hs.cairo
        # hs.diagrams
        hs.haskell-language-server
        myHaskellPackages.cabal-install
        # myHaskellPackages.stylish-haskell
        hs.hasktags
        # myHaskellPackages.hlint
        hs.stan
        pkgs.zlib
        hs.shelltestrunner
      ]);

    in rec {

      # packages.mptcpanalyzer = nixpkgs.legacyPackages.x86_64-linux.hello;
      packages.mptcpanalyzer = pkgs.stdenv.mkDerivation rec {
        name = "mptcpanalyzer";
        version = "0.1";
        src = ./.;

      buildInputs = with pkgs; [
        cairo # for chart-cairo
        dhall-json
        glib
        hsEnv
        pkg-config
        zlib
        replica.packages."${system}".build
        # inputs.replica
        # replica

      ];

      # see https://discourse.nixos.org/t/shared-libraries-error-with-cabal-repl-in-nix-shell/8921/9
      LD_LIBRARY_PATH = nixpkgs.lib.makeLibraryPath buildInputs;

    # # export HIE_HOOGLE_DATABASE=$NIX_GHC_DOCDIR as DOCDIR doesn't exist it won't work
      # export ASAN_OPTIONS="log_path=./test.log:abort_on_error=1"
      # export UBSAN_OPTIONS=print_stacktrace=1
    shellHook = ''
      # check if it's still needed ?
      export NVIM_LOG_FILE=/tmp/log

      ulimit -c unlimited
    '';

      };

      defaultPackage = packages.mptcpanalyzer;

    });
}
