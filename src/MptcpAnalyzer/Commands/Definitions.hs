module MptcpAnalyzer.Commands.Definitions
where
import MptcpAnalyzer.Commands.Utils
import MptcpAnalyzer.Definitions
import MptcpAnalyzer.Pcap

import Polysemy (Sem, Members, makeSem, interpret, Effect)

newtype ArgsLoadPcap = ArgsLoadPcap {
  loadPcap :: FilePath
}

data ParserSummary = ParserSummary {
  summaryFull :: Bool,
  summaryTcpStreamId :: StreamId Tcp
}

newtype ParserListSubflows = ParserListSubflows {
  listTcpDetailed :: Bool
  -- tcpStreamId :: StreamId Tcp
}

data ArgsPlot = ArgsPlot {

  plotOut :: String
  -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],
  -- , plotDisplay :: 
  , plotTitle :: Just String
  , plotToClipboard :: Just Bool
}

data Command m a where
  LoadCsv :: ArgsLoadPcap -> Command m RetCode
  LoadPcap :: ArgsLoadPcap -> Command m RetCode
  ListTcpConnections :: ParserListSubflows -> Command m RetCode
  ListMpTcpConnections :: ParserListSubflows -> Command m RetCode
  TcpSummary :: ParserSummary -> Command m RetCode
  PrintHelp :: Command m RetCode
  Plot :: Command m RetCode

makeSem ''Command
