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
    | ArgsListSubflows {
      _listSubflowsDetailed :: Bool
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
      plotArgs :: ArgsPlots
    }

    -- ArgsPlotTcpAttr {
    --   plotFilename :: FilePath
    --   , plotStreamId :: StreamId Tcp
    --   , plotDest :: Maybe ConnectionRole
    --   , plotOut :: Maybe String
    --   -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],
    --   -- , plotDisplay ::
    --   -- , plotTcpStreamId :: StreamId Tcp
    --   , plotTitle :: Maybe String
    --   , plotToClipboard :: Maybe Bool
    --   , plotDisplay :: Bool
    -- }



data RetCode = Exit | Error String | Continue

-- newtype ArgsLoadPcap = ArgsLoadPcap {
--   loadPcapPath :: FilePath
-- }

-- data ParserSummary = ParserSummary {
--   summaryFull :: Bool,
--   summaryTcpStreamId :: StreamId Tcp
-- }

-- newtype ParserListSubflows = ParserListSubflows {
--   listTcpDetailed :: Bool
--   -- tcpStreamId :: StreamId Tcp
-- }

-- data Command m a where
--   LoadCsv :: ArgsLoadPcap -> Command m RetCode
--   LoadPcap :: ArgsLoadPcap -> Command m RetCode
--   ListTcpConnections :: ParserListSubflows -> Command m RetCode
--   ListMpTcpConnections :: ParserListSubflows -> Command m RetCode
--   TcpSummary :: ParserSummary -> Command m RetCode
--   PrintHelp :: Command m RetCode
--   Plot :: ArgsPlot -> Command m RetCode

-- makeSem ''Command
