let Replica = https://raw.githubusercontent.com/berewt/REPLica/main/dhall/replica.dhall

in {

  list-mptcp = Replica.Minimal::{command = "mptcpanalyzer \"load-pcap examples/client_2_filtered.pcapng\" \"tcp-summary --full 0\"" },
  map-mptcp = Replica.Minimal::{command = "mptcpanalyzer \"map-mptcp examples/client_2_filtered.pcapng examples/server_2_filtered.pcapng 0\""},

  plot-owd = Replica.Minimal::{command = "mptcpanalyzer \"plot owd examples/client_2_filtered.pcapng examples/server_2_filtered.pcapng 0 0\""}
}
