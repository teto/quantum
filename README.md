https://hackage.haskell.org/package/Frames



```
cabal configure --enable-profiling
cabal run mptcpanalyzer "load-pcap examples/client_2_filtered.pcapng"  -- +RTS
-xc
```

Install zsh
--zsh-completion-script


# How to use
`cabal run mptcpanalyzer`
`plot --display tcp examples/client_2_filtered.pcapng 0 tcpseq`
```
mptcpanalyzer "map-tcp examples/client_2_filtered.pcapng examples/server_2_filtered.pcapng 0"
mptcpanalyzer "load-pcap examples/client_2_filtered.pcapng"
```

I use [vd](visidata).

# How to develop

Enter the nix-shell then run your typical cabal commands
```
$ nix-shell
$ cabal build
```
## Dependencies

- [haskell-chart](haskell-chart) with the svg backend

## Debug splices

`-ddump-splices -ddump-to-file -dth-dec-file`



# How to contribute ?

##  Run the tests

make test-integration





https://www.wireshark.org/docs/dfref/m/mptcp.html
visidata: https://www.visidata.org/
diagrams: https://hackage.haskell.org/package/diagrams
shelltestrunner: https://github.com/simonmichael/shelltestrunner
