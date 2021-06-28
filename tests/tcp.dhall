let Replica = https://raw.githubusercontent.com/berewt/REPLica/main/dhall/replica.dhall
let args = "--log-level Info"
in {

  list-tcp = Replica.Minimal::{
    command = ''
      mptcpanalyzer "load-pcap examples/client_2_filtered.pcapng" "tcp-summary --full 0" "quit"
      ''
    , tags = [ "tcp" ]
  },
  map-tcp = Replica.Minimal::{
    command = ''
      mptcpanalyzer "map-tcp examples/client_2_filtered.pcapng examples/server_2_filtered.pcapng 0" "quit"
      ''
    , tags = [ "tcp" ]
  }
}

