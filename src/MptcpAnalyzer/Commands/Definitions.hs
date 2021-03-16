module MptcpAnalyzer.Commands.Definitions
where
import MptcpAnalyzer.Commands.Utils ()
import MptcpAnalyzer.Types ()
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Plots.Types

-- import Polysemy (Sem, Members, makeSem, interpret, Effect)

-- | Registered commands
-- TODO make it possible to add some from a plugin
data CommandArgs = ArgsLoadCsv {
      _loadCsvPath :: FilePath
    }
    | ArgsLoadPcap {
        loadPcapPath :: FilePath
    }
    | ArgsListTcpConnections {
      _listTcpDetailed :: Bool
    }
    | ArgsListMpTcpConnections {
      _listMpTcpDetailed :: Bool
    }
    | ArgsMapTcpConnections {
      argsMapPcap1 :: FilePath
      , argsMapPcap2 :: FilePath
      , argsMapTcpStream :: StreamId Tcp
    }
    | ArgsListSubflows {
      _listSubflowsDetailed :: Bool
    }
    | ArgsListReinjections {
      injStream :: StreamId Mptcp
    }
    | ArgsParserSummary {
      summaryFull :: Bool,
      summaryTcpStreamId :: StreamId Tcp
      -- hidden file
    }
    | ArgsExport {
      argsExportFilename :: FilePath
    }
    | ArgsPlotGeneric {
      plotOut :: Maybe String
  --     , plotToClipboard :: Maybe Bool
  -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],
      , plotTitle :: Maybe String  -- ^ To override default title of the plot
      , plotDisplay :: Bool  -- ^Defaults to false
      , plotArgs :: ArgsPlots
    }

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
