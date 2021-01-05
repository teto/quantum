module MptcpAnalyzer.Commands.Definitions
where
import MptcpAnalyzer.Commands.Utils
import MptcpAnalyzer.Definitions
import MptcpAnalyzer.Pcap

import Polysemy (Sem, Members, makeSem, interpret, Effect)

newtype ArgsLoadPcap = ArgsLoadPcap {
  pcap :: FilePath
}

data ParserListSubflows = ParserListSubflows {
  full :: Bool,
  tcpStreamId :: StreamId Tcp
}

data Command m a where
  LoadCsv :: ArgsLoadPcap -> Command m RetCode
  LoadPcap :: ArgsLoadPcap -> Command m RetCode
  ListTcpConnections :: ParserListSubflows -> Command m RetCode
  TcpSummary :: ParserListSubflows -> Command m RetCode
  PrintHelp :: Command m RetCode

makeSem ''Command
