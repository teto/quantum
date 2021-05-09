module MptcpAnalyzer.Commands.Definitions
where
import MptcpAnalyzer.Types ()
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Plots.Types

import Data.Word (Word32)

-- import Polysemy (Sem, Members, makeSem, interpret, Effect)

-- | Registered commands
-- TODO make it possible to add some from a plugin
data CommandArgs =
    ArgsLoadCsv FilePath
    | ArgsHelp
    | ArgsQuit
    | ArgsLoadPcap FilePath
    | ArgsListTcpConnections Bool  -- ^ Detailed
    | ArgsListMpTcpConnections Bool  -- ^ Detailed
    | ArgsMapTcpConnections FilePath FilePath Word32 Bool Int Bool
    -- ^ Pcap 1
    -- ^ Pcap 2
    -- | ArgsMapMptcpConnections FilePath FilePath Word32 Bool Int Bool
      -- argsMapPcap1 :: FilePath
      -- , argsMapPcap2 :: FilePath
      -- , argsMapStream :: Word32
      -- , argsMapVerbose :: Bool
      -- , argsMapLimit :: Int -- ^Number of comparisons to show
      -- , argsMapMptcp :: Bool -- ^Wether it's an MPTCP
    -- }
    | ArgsListSubflows Bool
      -- ^ _listSubflowsDetailed
    | ArgsListReinjections (StreamId Mptcp)
    | ArgsParserSummary Bool (StreamId Tcp)
      -- summaryFull and summaryTcpStreamId
    | ArgsExport FilePath   -- ^ argsExportFilename
    -- | plotOut
    | ArgsPlotGeneric (Maybe String) (Maybe String) Bool ArgsPlots
    -- {
    --   plotOut :: Maybe String 
  -- --     , plotToClipboard :: Maybe Bool
  -- -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],
    --   , plotTitle :: Maybe String  -- ^ To override default title of the plot
    --   , plotDisplay :: Bool  -- ^Defaults to false
    --   , plotArgs :: ArgsPlots
    -- }
    | ArgsQualifyReinjections FilePath (StreamId Mptcp) FilePath (StreamId Mptcp) Bool
      -- ^ pcap1 stream1 pcap2 stream2 verbose
      -- qrPcap1 :: FilePath
      -- , qrStream1 :: StreamId Mptcp
      -- , qrPcap2 :: FilePath
      -- , qrStream2 :: StreamId Mptcp
      -- , qrVerbose :: Bool
      -- , qrLimit :: Int -- ^Number of comparisons to show
      -- , qrMptcp :: Bool -- ^Wether it's an MPTCP
    -- }

-- | Return code for user command. Whether to exit program/
data RetCode = Exit | Error String | Continue

-- data Command m a where
--   LoadCsv :: ArgsLoadPcap -> Command m RetCode
--   LoadPcap :: ArgsLoadPcap -> Command m RetCode
--   ListTcpConnections :: ParserListSubflows -> Command m RetCode
--   ListMpTcpConnections :: ParserListSubflows -> Command m RetCode
--   TcpSummary :: ParserSummary -> Command m RetCode
--   PrintHelp :: Command m RetCode
--   Plot :: ArgsPlot -> Command m RetCode

-- makeSem ''Command
