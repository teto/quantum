module Net.Mptcp.Connection
where


data MptcpConnection = MptcpConnection {
      -- todo prefix as mpcon
      mptcpStreamId :: StreamIdMptcp
      , mptcpServerKey :: Word64
      , mptcpClientKey :: Word64
      , mptcpServerToken :: Word32
      , mptcpClientToken :: Word32
      , mptcpNegotiatedVersion :: Word8
      -- should be a subflow
      , mpconSubflows :: Set.Set MptcpSubflow

-- Ord to be able to use fromList
} deriving (Show, Eq, Ord)

data MptcpSubflow = MptcpSubflow {
      sfConn :: TcpConnection
      , sfMptcpDest :: ConnectionRole -- ^ Destination
      , sfPriority :: Maybe Word8 -- ^subflow priority
      , sfLocalId :: Word8  -- ^ Convert to AddressFamily
      , sfRemoteId :: Word8
      --conTcp TODO remove could be deduced from srcIp / dstIp ?
      , sfInterface :: Text -- ^Interface of Maybe ? why a maybe ?
    } deriving (Show, Eq, Ord)
