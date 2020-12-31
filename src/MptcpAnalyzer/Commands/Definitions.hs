module MptcpAnalyzer.Commands.Definitions
where
import MptcpAnalyzer.Commands.Utils

import Polysemy (Sem, Members, makeSem, interpret, Effect)

newtype ArgsLoadPcap = ArgsLoadPcap {
  pcap :: FilePath
}

data ParserListSubflows = ParserListSubflows {
  full :: Bool,
  tcpStreamId :: StreamId Tcp
}
-- Phantom types
data Mptcp
data Tcp

-- TODO use Word instead
newtype StreamId a = StreamId Int deriving (Show, Read, Eq, Ord)

data Command m a where
  LoadCsv :: ArgsLoadPcap -> Command m RetCode
  LoadPcap :: ArgsLoadPcap -> Command m RetCode
  ListTcpConnections :: ParserListSubflows -> Command m RetCode
  PrintHelp :: Command m RetCode

makeSem ''Command
