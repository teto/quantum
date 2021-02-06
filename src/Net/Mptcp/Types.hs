{-# LANGUAGE OverloadedStrings #-}
module Net.Mptcp.Types
where

import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as TS
import Data.Word (Word8, Word16, Word32, Word64)
import Net.IP
import Net.Tcp

-- type MptcpSendKey = Word64

-- For now... for convenience only
type MptcpSubflow = TcpConnection

-- | Overrides the MptcpConnection from
-- mptcp-pm (for backwards compatibility:
-- remove it later on)
data MptcpConnection = MptcpConnection {
  mptcpServerKey :: Word64
  , mptcpClientKey :: Word64
  , mptcpServerToken :: Word32
  , mptcpClientToken :: Word32
  , mptcpNegotiatedVersion :: Word8

  -- master subflow
  -- use SubflowWithMetrics instead ?!
  -- , subflows :: Set.Set [TcpConnection]
  -- TODO use MptcpSubflow instead ?
  , subflows :: Set.Set MptcpSubflow
  , localIds :: Set.Set Word8  -- ^ Announced addresses
  , remoteIds :: Set.Set Word8   -- ^ Announced addresses

} deriving Show

tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show

showMptcpConnectionText :: MptcpConnection -> TS.Text
showMptcpConnectionText con =
  -- showIp (srcIp con) <> ":" <> tshow (srcPort con) <> " -> " <> showIp (dstIp con) <> ":" <> tshow (dstPort con)
  tpl
  where
    -- showIp = Net.IP.encode
    -- masterSf :: TcpConnection
    -- masterSf =

    -- todo show server key/
    tpl :: Text
    tpl = "Server key/token: " <> tshow (mptcpServerKey con) <> "/" <> tshow ( mptcpServerToken con) <> "Client key/token: " <> tshow (mptcpClientKey con) <> "/" <> tshow ( mptcpClientToken con)


showMptcpConnection :: MptcpConnection -> String
showMptcpConnection = TS.unpack . showMptcpConnectionText

