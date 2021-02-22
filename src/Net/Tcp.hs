module Net.Tcp
where

streamPackets -> PcapFrame -> StreamId Tcp -> PcapFrameF Tcp
streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId) frame


