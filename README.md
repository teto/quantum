<!-- BEGIN-MARKDOWN-TOC -->
* [Presentation](#presentation)
* [Installation](#installation)
* [Help](#faq)
* [Related tools](#related_tools)

<!-- END-MARKDOWN-TOC -->


Presentation
===

Mptcpanalyzer is a tool conceived to help with MPTCP pcap analysis (as [mptcptrace] for instance).

It accepts packet capture files (\*.pcap) as inputs and from there you can:

- list MPTCP connections
- compute statistics on a specific MPTCP connection (list of subflows, reinjections, subflow actual contributions...)
- export a CSV file with MPTCP fields
- plot one way delays
- ...

Commands are self documented with autocompletion.
The interpreter with autocompletion that can generate & display plots such as the following:

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

- [polysemy](polysemy) to handle effects
- [Frames](frames) to analyze data
- [haskell-chart](haskell-chart) with the svg backend
- [wireshark](wireshark-mptcp) to convert packet captures (.pcapng) to csv
files.

## Debug splices

`-ddump-splices -ddump-to-file -dth-dec-file`



# How to contribute ?

##  Run the tests

make test-integration


# Related tools

Similar software:

| Tool             | Description                                                                       |
|------------------------|-------------------------------------------------------------------------------|
| [mptcptrace]             | C based: [an example](http://blog.multipath-tcp.org/blog/html/2015/02/02/mptcptrace_demo.html)                                               |
| [mptcpplot]       | C based developed at NASA: [generated output example](https://roland.grc.nasa.gov/~jishac/mptcpplot/)                                                 |



[mptcptrace]: https://bitbucket.org/bhesmans/mptcptrace
[mptcpplot]: https://github.com/nasa/multipath-tcp-tools/
wireshark-mptcp: https://www.wireshark.org/docs/dfref/m/mptcp.html
polysemy: https://hackage.haskell.org/package/polysemy
visidata: https://www.visidata.org/
diagrams: https://hackage.haskell.org/package/diagrams
frames: https://hackage.haskell.org/package/Frames
shelltestrunner: https://github.com/simonmichael/shelltestrunner
