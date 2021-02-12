let
  overlay = self: prev: {
      haskell = prev.haskell // {
        packageOverrides = hnew: hold: with prev.haskell.lib;{

          ip = dontCheck hold.ip;
          bytebuild = dontCheck hold.bytebuild;

          # for newer nixpkgs (March 2020)
          # base-compat = doJailbreak (hold.base-compat);
          # time-compat = doJailbreak (hold.time-compat);
          # mptcp-pm = (overrideSrc hold.mptcp-pm {
          #   src = prev.fetchFromGitHub {
          #     owner = "teto";
          #     repo = "mptcp-pm";
          #     rev = "4087bd580dcb08919e8e3bc78ec3b25d42ee020d";
          #     sha256 = "sha256-MiXbj2G7XSRCcM0rnLrbO9L5ZFyh6Z3sPtnH+ddInI8=";
          #   };
          # });
          netlink = (overrideSrc hold.netlink {
            # src = builtins.fetchGit {
            #   # url = https://github.com/ongy/netlink-hs;
            #   url = https://github.com/teto/netlink-hs;
            # };
            src = prev.fetchFromGitHub {
              owner = "teto";
              repo = "netlink-hs";
              rev = "090a48ebdbc35171529c7db1bd420d227c19b76d";
              sha256 = "sha256-qopa1ED4Bqk185b1AXZ32BG2s80SHDSkCODyoZfnft0=";
            };
          });
        };
      };
  };

  nixpkgsRev = "758b29b5a28b818e311ad540637a5c1e40867489";
  # pinned nixpkgs before cabal 3 becomes the default else hie fails
  # nixpkgs = import <nixpkgs>
  nixpkgs = import (builtins.fetchTarball {
      name = "nixos-unstable";
      url = "https://github.com/nixos/nixpkgs/archive/${nixpkgsRev}.tar.gz";
      sha256 = "00nk1a002zzi0ij4xp2hf7955wj49qdwsm2wy7mzbpjbgick6scp";
  })
  {
    overlays = [ overlay]; config = {allowBroken = true;};
  };
in
  nixpkgs
