module MptcpAnalyzer.Plots.Types
where

import MptcpAnalyzer.Types

data PlotSettings = PlotSettings {
  ploTitle :: String
  , ploLabelx :: String
  , ploLabely :: String
  -- Tshark config ? why
  }


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
      , plotStreamId :: StreamId Tcp
      , plotDest :: Maybe ConnectionRole
      , plotOut :: Maybe String
      -- parser.add_argument('--display', action="store", default="term", choices=["term", "gui", "no"],
      -- , plotDisplay ::
      -- , plotTcpStreamId :: StreamId Tcp
      , plotTitle :: Maybe String
      , plotToClipboard :: Maybe Bool
      , plotDisplay :: Bool
    }
