{
  description = "Multipath tcp pcap analyzer tool";

  nixConfig = {
    substituters = [  https://hydra.iohk.io ];
    # bash-prompt = "toto";
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/master";
    replica.url = "github:berewt/REPLica";

    # temporary until this gets fixed upstream
    # poetry.url = "github:teto/poetry2nix/fix_tag";

    flake-utils.url = "github:numtide/flake-utils";

    hls.url = "github:haskell/haskell-language-server";
    # hls.url = "github:teto/haskell-language-server/flake-debug";

    # haskellNix.url = "github:input-output-hk/haskell.nix?ref=hkm/nixpkgs-unstable-update";
    haskellNix.url = "github:input-output-hk/haskell.nix";
  };

  outputs = { self, nixpkgs, flake-utils, poetry, replica, ... }@inputs:
    flake-utils.lib.eachSystem ["x86_64-linux"] (system: let

      haskellOverlay = hnew: hold: with pkgs.haskell.lib; {

        # TODO override Frames
        ip = unmarkBroken (dontCheck hold.ip);
        bytebuild = unmarkBroken (dontCheck hold.bytebuild);
        wide-word = unmarkBroken (dontCheck hold.wide-word);

        co-log-polysemy = doJailbreak (hold.co-log-polysemy);
        # hls-lint-plugin = doJailbreak (hold.hls-lint-plugin);

        netlink = (overrideSrc hold.netlink {
          # src = builtins.fetchGit {
          #   # url = https://github.com/ongy/netlink-hs;
          #   url = https://github.com/teto/netlink-hs;
          # };
          version = "1.1.2.0";
          src = pkgs.fetchFromGitHub {
            owner = "teto";
            repo = "netlink-hs";
            rev = "090a48ebdbc35171529c7db1bd420d227c19b76d";
            sha256 = "sha256-qopa1ED4Bqk185b1AXZ32BG2s80SHDSkCODyoZfnft0=";
          };
        });

        mptcp-pm = overrideSrc hold.mptcp-pm {
          src = pkgs.fetchFromGitHub {
            owner = "teto";
            repo = "mptcp-pm";
            rev = "0cd4cad9bab5713ebbe529e194bddb08948825d7";
            sha256 = "sha256-7JhrMrv9ld12nx8LyfOuOPTBb7RyWIwSWNB9vWDe/g0=";
          };
        };

      };

      compilerVersion = "8104";
      # compilerVersion = "901";

      # pkgs = nixpkgs.legacyPackages."${system}";
      pkgs = import nixpkgs {
          inherit system;
          # overlays = pkgs.lib.attrValues (self.overlays);
          config = { allowUnfree = true; allowBroken = true; };
        };

      myHaskellPackages = pkgs.haskell.packages."ghc${compilerVersion}";

      hsEnv = myHaskellPackages.ghcWithPackages(hs: [
        # hs.cairo
        # hs.diagrams
        # inputs.hls.packages."${system}"."haskell-language-server-${compilerVersion}"
        hs.cabal-install
        hs.stylish-haskell
        hs.hasktags
        # myHaskellPackages.hlint
        hs.stan
        pkgs.zlib
        hs.shelltestrunner
      ]);

    in rec {

      packages.mptcpanalyzer = pkgs.haskellPackages.developPackage {
        root = ./.;
        name = "mptcpanalyzer";
        returnShellEnv = false;
        withHoogle = true;
        overrides = haskellOverlay;
      };

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
      # packages.mptcppm =
      # devShell = pkgs.haskellPackages.developPackage {
      #   root = ./.;
      #   name = "mptcp-pm";
      #   returnShellEnv = false;
      #   withHoogle = true;
      #   overrides = haskellOverlay;
      #   modifier = drv:
      #     pkgs.haskell.lib.addBuildTools drv (with pkgs;
      #     [
      #       # ghcid
      #       haskellPackages.cabal-install
      #       haskellPackages.c2hs
      #       haskellPackages.stylish-haskell
      #       haskellPackages.hlint
      #       # haskellPackages.haskell-language-server
      #       haskellPackages.hasktags
      #       hls.packages."${system}"."haskell-language-server-${compilerVersion}"
      #     ]);
      # };

      devShell = pkgs.mkShell {
        name = "dev-shell";
        buildInputs = with pkgs; [
          # defaultPackage.inputDerivation
          replica.packages."${system}".build
          inputs.hls.packages."${system}"."haskell-language-server-${compilerVersion}"
          cairo # for chart-cairo
          dhall-json  # for dhall-to-json
          glib
          hsEnv
          pkg-config
          zlib
        ];

        shellHook = ''
          exe=$(cabal list-bin exe:mptcpanalyzer)
          PATH="$(dirname $exe):$PATH"
        '';
      };

    });
}
