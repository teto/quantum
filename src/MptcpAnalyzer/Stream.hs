{-# LANGUAGE DerivingVia         #-}
{-# LANGUAGE DerivingStrategies         #-}
module MptcpAnalyzer.Stream
where
import Data.Word (Word32)
import Data.Hashable

-- Phantom types
data Mptcp
data Tcp
-- data Protocol = Tcp | Mptcp
-- type TcpFlagList = [TcpFlag]

-- TODO use Word instead
newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord ) deriving Hashable via Word32
type StreamIdTcp = StreamId Tcp
type StreamIdMptcp = StreamId Mptcp

