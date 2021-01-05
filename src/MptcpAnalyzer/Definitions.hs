{-# LANGUAGE TemplateHaskell            #-}
module MptcpAnalyzer.Definitions
where

import MptcpAnalyzer.Pcap
-- import Lens.Micro
import Control.Lens
import Options.Applicative
import Data.Word (Word32)

-- |Helper to pass information across functions
data MyState = MyState {
  _cacheFolder :: FilePath

  , _loadedFile   :: Maybe PcapFrame  -- ^ cached loaded pcap
  , _prompt   :: String  -- ^ cached loaded pcap
}

makeLenses ''MyState



defaultParserPrefs :: ParserPrefs
defaultParserPrefs = defaultPrefs

