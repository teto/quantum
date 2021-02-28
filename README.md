https://hackage.haskell.org/package/Frames



```
cabal configure --enable-profiling
cabal run mptcpanalyzer "load-pcap examples/client_2_filtered.pcapng"  -- +RTS
-xc
```

Install zsh
--zsh-completion-script

# How to develop

Enter the nix-shell then run your typical cabal commands
```
$ nix-shell
$ cabal build
```
## Dependencies

- [Diagrams](diagrams) with the svg backend

## Debug splices

`-ddump-splices -ddump-to-file -dth-dec-file`



# How to use ?

Integration with wireshark is not there yet, csv file has to be regenerated
manually. I use [vd](visidata).



https://www.wireshark.org/docs/dfref/m/mptcp.html
visidata: https://www.visidata.org/
diagrams: https://hackage.haskell.org/package/diagrams
