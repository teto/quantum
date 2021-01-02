{-# LANGUAGE TemplateHaskell            #-}
module MptcpAnalyzer.Definitions
where

import Pcap
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

-- Phantom types
data Mptcp
data Tcp

-- TODO use Word instead
newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord)

defaultParserPrefs :: ParserPrefs
defaultParserPrefs = defaultPrefs

