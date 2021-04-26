module MptcpAnalyzer.Plots.Types
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.ArtificialFields
import Data.Word (Word32)

data PlotSettings = PlotSettings {
  ploTitle :: String
  , ploLabelx :: String
  , ploLabely :: String
  -- Tshark config ? why
  }
      -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],


--
data ArgsPlots = 
  -- ArgsPlots  {
  --     plotOut :: Maybe String
  --     -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],
  --     -- , plotDisplay ::
  --     -- , plotTcpStreamId :: StreamId Tcp
  --     , plotTitle :: Maybe String
  --     , plotToClipboard :: Maybe Bool
  --     , plotDisplay :: Bool
  -- }

    -- actually valid for MPTCP too
    ArgsPlotTcpAttr {
      plotField :: String
      , plotFilename :: FilePath
      -- try to pattern match on the StreamId
      , plotStreamId :: Word32
      , plotTcpAttr :: String
      , plotDest :: Maybe ConnectionRole
      , plotMptcp :: Bool -- ^ hidden option
    }
    | ArgsPlotOwd {
      plotOwdPcap1 :: FilePath
      , plotOwdPcap2 :: FilePath
      -- try to pattern match on the StreamId
      , plotOwdStreamId1 :: Word32
      , plotOwdStreamId2 :: Word32
      , plotOwdDest :: Maybe ConnectionRole
      -- , plotOwdMptcp :: Bool -- ^ hidden option
    }
    --
    --
    -- ArgsPlotMptcpAttr {
    --     plotAttrMptcpFilename :: FilePath
    --   , plotAttrMptcpStreamId :: StreamId Mptcp
    --   , plotAttrMptcpAttr :: String
    --   , plotAttrMptcpDest :: Maybe ConnectionRole
    -- }
