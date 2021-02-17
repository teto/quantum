{-# LANGUAGE TemplateHaskell            #-}
module MptcpAnalyzer.Definitions
where

import MptcpAnalyzer.Pcap
-- import Lens.Micro
import Control.Lens
import Options.Applicative

-- |Helper to pass information across functions
data MyState = MyState {
  _stateCacheFolder :: FilePath

  , _loadedFile   :: Maybe PcapFrame  -- ^ cached loaded pcap
  , _prompt   :: String  -- ^ cached loaded pcap
}

makeLenses ''MyState



-- alternatively could modify defaultPrefs
defaultParserPrefs :: ParserPrefs
defaultParserPrefs = prefs showHelpOnEmpty
-- {
--     prefShowHelpOnError = True
--     }

