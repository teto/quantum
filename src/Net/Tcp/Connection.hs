module Net.Tcp.Connection
where

data TcpConnection = TcpConnection {
--   -- TODO use libraries to deal with that ? filter from the command line for instance ?
  conTcpClientIp :: IP -- ^Client ip
  , conTcpServerIp :: IP -- ^Server ip
  , conTcpClientPort :: Word16  -- ^ Source port
  , conTcpServerPort :: Word16  -- ^Destination port
  , conTcpStreamId :: StreamId Tcp  -- ^ @tcp.stream@ in wireshark
  } deriving (Show, Eq, Ord)

tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show


showTcpConnectionText :: TcpConnection -> Text
showTcpConnectionText con =
  showIp (conTcpClientIp con) <> ":" <> tshow (conTcpClientPort con) <> " -> "
      <> showIp (conTcpServerIp con) <> ":" <> tshow (conTcpServerPort con)
      <> " (tcp.stream: " <> showStream (conTcpStreamId con) <> ")"
  where
    showIp = Net.IP.encode
    showStream (StreamId a) = tshow a
