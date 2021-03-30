# from https://github.com/NixOS/nixpkgs/blob/master/doc/languages-frameworks/haskell.section.md
{
  nixpkgs ? import ./pinned_nixpkgs.nix
  # nixpkgs ? import <nixpkgs> {}
  # , compilerName ? "ghc8101" # not supported yet
  # , compilerName ? "ghc8104"
  # , compilerName ? "ghc901"
  , compilerName ? "ghc884"
}:

let
  # compiler = pkgs.haskell.packages."${compilerName}";
  pkgs = nixpkgs.pkgs;

  hsEnv = myHaskellPackages.ghcWithPackages(hs: [
    # hs.cairo
    # hs.diagrams
    hs.haskell-language-server
    myHaskellPackages.cabal-install
    # myHaskellPackages.stylish-haskell
    hs.hasktags
    # myHaskellPackages.hlint
    # haskellPackages.stan  # broken
    pkgs.zlib
    hs.shelltestrunner
  ]);
  # my_pkg = (import ./. { inherit compiler; } );
  myHaskellPackages = pkgs.haskell.packages."${compilerName}";
in
  pkgs.mkShell rec {
    name = "quantum";
    buildInputs = with pkgs; [
      cairo # for chart-cairo
      glib
      hsEnv
      pkg-config
      zlib
    ];

    # see https://discourse.nixos.org/t/shared-libraries-error-with-cabal-repl-in-nix-shell/8921/9
    LD_LIBRARY_PATH = nixpkgs.lib.makeLibraryPath buildInputs;

  # # export HIE_HOOGLE_DATABASE=$NIX_GHC_DOCDIR as DOCDIR doesn't exist it won't work
  shellHook = ''
    # check if it's still needed ?
    export NVIM_LOG_FILE=/tmp/log

    export ASAN_OPTIONS="log_path=./test.log:abort_on_error=1"
    export UBSAN_OPTIONS=print_stacktrace=1
  '';
  }
