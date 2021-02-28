-- TODO reexport stuff ?
module MptcpAnalyzer.Frame
where

import MptcpAnalyzer.Types

-- Specialize depending on StreamId
-- filterStreamPackets :: SomeFrame -> StreamId Tcp -> Maybe ConnectionRole  -> SomeFrameF Tcp
-- filterStreamPackets frame streamId role =

--   filterFrame
--   where
--     streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId) frame



