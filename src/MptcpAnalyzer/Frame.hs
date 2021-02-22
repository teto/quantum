-- TODO reexport stuff ?
module MptcpAnalyzer.Frame
where

import MptcpAnalyzer.Types

-- Specialize depending on StreamId
-- filterStreamPackets :: PcapFrame -> StreamId Tcp -> Maybe ConnectionRole  -> PcapFrameF Tcp
-- filterStreamPackets frame streamId role =

--   filterFrame
--   where
--     streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId) frame



