module MptcpAnalyzer.Plots.Types
where

import MptcpAnalyzer.Types
import Data.Word (Word32)

data PlotSettings = PlotSettings {
  ploTitle :: String
  , ploLabelx :: String
  , ploLabely :: String
  -- Tshark config ? why
  }
      -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],


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

    ArgsPlotTcpAttr {
      plotFilename :: FilePath
      , plotStreamId :: Word32
      , plotTcpAttr :: String
      , plotDest :: Maybe ConnectionRole
    }

    -- | ArgsPlotMptcpAttr {
    --     plotAttrMptcpFilename :: FilePath
    --   , plotAttrMptcpStreamId :: StreamId Mptcp
    --   , plotAttrMptcpAttr :: String
    --   , plotAttrMptcpDest :: Maybe ConnectionRole
    -- }
