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
  ]);
  # my_pkg = (import ./. { inherit compiler; } );
  myHaskellPackages = pkgs.haskell.packages."${compilerName}";
in
    pkgs.mkShell {
    name = "quantum";
    buildInputs = with pkgs; [
      # cairo
      glib
      hsEnv
      pkg-config
      zlib
      zlib.dev

      pkgs.llvm_11  # for llvm-symbolizer
    ];

  # (my_pkg.envFunc { withHoogle = true; }).overrideAttrs (oa: {
  #   nativeBuildInputs = oa.nativeBuildInputs ++ (with pkgs; [
  #     haskellPackages.cabal-install
  #     haskellPackages.hasktags
  #     haskellPackages.hlint
  #     # haskellPackages.nvim-hs-ghcid # too old, won't support nvim-hs-contrib 2
  #   ]);

  # # export HIE_HOOGLE_DATABASE=$NIX_GHC_DOCDIR as DOCDIR doesn't exist it won't work
  # # shellHook = "eval $(grep export ${ghc}/bin/ghc)";
  # # export PATH="${my_nvim}/bin:$PATH"
  # # --package-db /home/teto/netlink-hs/dist/package.conf.inplace
  # # --package-db /home/teto/mptcppm/dist/package.conf.inplace
  #     export HIE_HOOGLE_DATABASE="$NIX_GHC_LIBDIR/../../share/doc/hoogle/index.html"

  # ASAN_OPTIONS=abort_on_error=1
  # halt_on_error=0"
  shellHook = ''
    # check if it's still needed ?
    export NVIM_LOG_FILE=/tmp/log

    export ASAN_OPTIONS="log_path=./test.log:abort_on_error=1"
    export UBSAN_OPTIONS=print_stacktrace=1
  '';
  }
