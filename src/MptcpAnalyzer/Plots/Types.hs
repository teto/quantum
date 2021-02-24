module MptcpAnalyzer.Plots.Types
where

data Plot = Plot {
  ploTitle :: String
  , ploLabelx :: String
  , ploLabely :: String
  -- Tshark config ? why
  }
