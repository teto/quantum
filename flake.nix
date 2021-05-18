{
  description = "Multipath tcp pcap analyzer tool";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    replica.url = "github:berewt/REPLica";

    # temporary until this gets fixed upstream
    # poetry.url = "github:teto/poetry2nix/fix_tag";

    flake-utils.url = "github:numtide/flake-utils";

    hls.url = "github:haskell/haskell-language-server/nix-flakes";
  };

  outputs = { self, nixpkgs, flake-utils, poetry, replica, ... }@inputs:
    flake-utils.lib.eachSystem ["x86_64-linux"] (system: let

      haskellOverlay = hnew: hold: with pkgs.haskell.lib; {

        # TODO override Frames
        ip = unmarkBroken (dontCheck hold.ip);
        bytebuild = unmarkBroken (dontCheck hold.bytebuild);
        wide-word = unmarkBroken (dontCheck hold.wide-word);

        netlink = (overrideSrc hold.netlink {
          # src = builtins.fetchGit {
          #   # url = https://github.com/ongy/netlink-hs;
          #   url = https://github.com/teto/netlink-hs;
          # };
          src = pkgs.fetchFromGitHub {
            owner = "teto";
            repo = "netlink-hs";
            rev = "090a48ebdbc35171529c7db1bd420d227c19b76d";
            sha256 = "sha256-qopa1ED4Bqk185b1AXZ32BG2s80SHDSkCODyoZfnft0=";
          };
        });
      };

      compilerVersion = "8104";
      pkgs = nixpkgs.legacyPackages."${system}";

      myHaskellPackages = pkgs.haskell.packages."ghc${compilerVersion}";

      hsEnv = myHaskellPackages.ghcWithPackages(hs: [
        # hs.cairo
        # hs.diagrams
        # haskell-language-server-884
        inputs.hls.packages."${system}"."haskell-language-server-${compilerVersion}"
        hs.cabal-install
        # myHaskellPackages.stylish-haskell
        hs.hasktags
        # myHaskellPackages.hlint
        hs.stan
        pkgs.zlib
        hs.shelltestrunner
      ]);

    in rec {

      # packages.mptcpanalyzer = nixpkgs.legacyPackages.x86_64-linux.hello;
      # callCabal2nixWithOptions
      packages.mptcpanalyzer = myHaskellPackages.callCabal2nix "mptcpanalyzer" ./. {};

      # packages.mptcpanalyzer = pkgs.stdenv.mkDerivation rec {
      #   name = "mptcpanalyzer";
      #   version = "0.1";
      #   src = ./.;
      #   buildInputs = with pkgs; [
      #     cairo # for chart-cairo
      #     dhall-json  # for dhall-to-json
      #     glib
      #     hsEnv
      #     pkg-config
      #     zlib
      #   ];

      #   # see https://discourse.nixos.org/t/shared-libraries-error-with-cabal-repl-in-nix-shell/8921/9
      #   LD_LIBRARY_PATH = nixpkgs.lib.makeLibraryPath buildInputs;

      # # # export HIE_HOOGLE_DATABASE=$NIX_GHC_DOCDIR as DOCDIR doesn't exist it won't work
      #   # export ASAN_OPTIONS="log_path=./test.log:abort_on_error=1"
      #   # export UBSAN_OPTIONS=print_stacktrace=1
      #   shellHook = ''
      #     # check if it's still needed ?
      #     export NVIM_LOG_FILE=/tmp/log

      #     ulimit -c unlimited
      #   '';
      # };

      defaultPackage = packages.mptcpanalyzer;

      devShell = pkgs.mkShell {
        name = "dev-shell";
        buildInputs = [
          # poetry.packages."${system}".poetry
          defaultPackage.inputDerivation
          replica.packages."${system}".build
          inputs.hls.packages."${system}"."haskell-language-server-${compilerVersion}"
        ];
      };

    });
}
