module MptcpAnalyzer.Plots.Types
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.ArtificialFields
import Data.Word (Word32)

-- {
--   plotOut :: Maybe String 
-- --     , plotToClipboard :: Maybe Bool
-- -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],
--   , plotTitle :: Maybe String  -- ^ To override default title of the plot
--   , plotDisplay :: Bool  -- ^Defaults to false
--   , plotArgs :: ArgsPlots
-- }
data PlotSettings = PlotSettings {
  plsOut :: Maybe String
  , plsTitle :: Maybe String
  , plsDisplay :: Bool
  -- , ploLabelx :: String
  -- , ploLabely :: String
  -- Tshark config ? why
  --
  , plsMptcp :: Bool -- mptcp
  }
      -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],

-- (Maybe String) (Maybe String) Bool
data ArgsPlots =

    -- actually valid for MPTCP too
    ArgsPlotTcpAttr {
      -- plotField :: String
      plotFilename :: FilePath
      -- try to pattern match on the StreamId
      , plotStreamId :: Word32
      , plotTcpAttr :: String
      , plotDest :: Maybe ConnectionRole
      -- , plotMptcp :: Bool -- ^ hidden option
    }
    -- |
    -- @pcap1 pcap2 stream1 stream2 destinations whether its tcp or mptcp
    | ArgsPlotOwd FilePath FilePath Word32 Word32 (Maybe ConnectionRole)
    -- | ArgsPlotOwd {
    --   plotOwdPcap1 :: FilePath
    --   , plotOwdPcap2 :: FilePath
    --   -- try to pattern match on the StreamId
    --   , plotOwdStreamId1 :: Word32
    --   , plotOwdStreamId2 :: Word32
    --   , plotOwdDest :: Maybe ConnectionRole
    --   -- , plotOwdMptcp :: Bool -- ^ hidden option
    -- }
    --
    --
    -- ArgsPlotMptcpAttr {
    --     plotAttrMptcpFilename :: FilePath
    --   , plotAttrMptcpStreamId :: StreamId Mptcp
    --   , plotAttrMptcpAttr :: String
    --   , plotAttrMptcpDest :: Maybe ConnectionRole
    -- }
