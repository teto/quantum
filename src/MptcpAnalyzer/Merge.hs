{- Merge 2 dataframes

-}
{-# LANGUAGE TypeApplications             #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE PolyKinds             #-}

module MptcpAnalyzer.Merge
where

import MptcpAnalyzer.Types

import Frames
import Frames.Joins
import Data.Vinyl
import Data.Vinyl.TypeLevel
import Data.Hashable
import GHC.TypeLits (KnownSymbol, Symbol)
import qualified Data.Vinyl as V
import Language.Haskell.TH (Name)
import Net.IP (IP)
import Data.Word (Word8, Word16, Word32, Word64)
import Tshark.TH
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Types
import Data.Maybe (catMaybes)
import Data.Foldable (toList)
import Control.Lens

-- convert_to_sender_receiver
-- merge_tcp_dataframes_known_streams(
-- map_tcp_packets_via_hash
-- map_mptcp_connection_from_known_streams(
-- classify reinjections

-- PacketMerged should be TCP/MPTCP


-- TODO use inner join / outer join hash
-- mapMptcpConnectionsFromKnownStreams :: FrameFiltered Packet -> FrameFiltered Packet -> FrameFiltered PacketMerged
-- mapMptcpConnectionsFromKnownStreams =

type Score = Int

-- | Computes a score
scoreTcpCon :: Connection -> Connection -> Score
scoreTcpCon con1@TcpConnection{} con2@TcpConnection{} =
  -- """
  -- If every parameter is equal, returns +oo else 0
  -- TODO also match on isn in case ports got reused
  -- """
  -- score = 0
  -- if (self.tcpserver_ip == other.tcpserver_ip
  --     and self.tcpclient_ip == other.tcpclient_ip
  --     and self.client_port == other.client_port
  --     and self.server_port == other.server_port):
  --     return float('inf')

  foldl (\acc toAdd -> acc + 10 * fromEnum toAdd) (0 :: Int) [
    conTcpClientIp con1 == conTcpClientIp con2
    , conTcpClientPort con1 == conTcpClientPort con2
    , conTcpServerIp con1 == conTcpServerIp con2
    , conTcpServerPort con1 == conTcpServerPort con2
  ]
-- scoreTcpCon con1@MptcpConnection{} con2@MptcpConnection{} = error "not implemented yet"
scoreTcpCon con1@MptcpConnection{} con2@MptcpConnection{} =
  let keyScore = if (mptcpServerKey con1 == mptcpServerKey con2 && mptcpClientKey con1 == mptcpClientKey con2) then
        200
      else
        0

    -- TODO compare subflow scores
    -- scoreSubflow = sum . map score
  in
    keyScore
--     def score(self, other: 'MpTcpConnection') -> float:
        -- """
        -- ALREADY FILTERED dataframes

        -- Returns:
        --     a score
        --     - '-inf' means it's not possible those 2 matched
        --     - '+inf' means
        -- """

        -- score = 0
        -- if len(self.subflows()) != len(other.subflows()):
        --     log.warn("Fishy ?! Datasets contain a different number of subflows (d vs d)" % ())
        --     score -= 5

        -- common_sf = []

        -- if (self.keys[ConnectionRoles.Server] == other.keys[ConnectionRoles.Server]
        --     and self.keys[ConnectionRoles.Client] == other.keys[ConnectionRoles.Client]):
        --     log.debug("matching keys => same")
        --     return float('inf')

        -- # TODO check there is at least the master
        -- # with nat, ips don't mean a thing ?
        -- for sf in self.subflows():
        --     if sf in other.subflows() or sf.reversed() in other.subflows():
        --         log.debug("Subflow %s in common", sf)
        --         score += 10
        --         common_sf.append(sf)
        --     else:
        --         log.debug("subflows %s doesn't seem to exist in other ", sf)

        -- # TODO compare start times supposing cloak are insync ?
        -- return score

-- def map_mptcp_connection_from_known_streams(
--     main: MpTcpConnection,
--     other: MpTcpConnection
-- ) -> MpTcpMapping:
--     """
--     Attempts to map subflows only if score is high enough
--     """
--     def _map_subflows(main: MpTcpConnection, mapped: MpTcpConnection):
--         """
--         """
--         mapped_subflows = []
--         for sf in main.subflows():

--             # generates a list (subflow, score)
--             scores = list(map(lambda x: TcpMapping(x, sf.score(x)), mapped.subflows()))
--             scores.sort(key=lambda x: x.score, reverse=True)
--             log.log(mp.TRACE, "sorted scores when mapping %s:\n %r" % (sf, scores))
--             mapped_subflows.append((sf, scores[0]))
--         return mapped_subflows

--     mptcpscore = main.score(other)
--     mapped_subflows = None
--     if mptcpscore > float('-inf'):
--         # (other, score)
--         mapped_subflows = _map_subflows(main, other)

--     mapping = MpTcpMapping(mapped=other, score=mptcpscore, subflow_mappings=mapped_subflows)
--     log.log(mp.TRACE, "mptcp mapping %s", mapping)
--     return mapping


scoreTcpCon _ _ = undefined

-- prefix
-- type PacketMerged =
toHashablePacket :: Record RecTshark -> Record HashablePart
toHashablePacket = rcast

-- instance Hashable (Rec ElField a) where

-- -- TODO should generate a column and add it back to RecTshark
-- -- type FieldRec = Rec ElField
-- addHash :: FrameFiltered Packet -> Frame (Record (PacketHash ': HashablePart))
-- addHash aframe =
--   fmap (addHash')  ( frame)
--   where
--     frame = fmap toHashablePacket (ffFrame aframe)
--     addHash' row = Col (hashWithSalt 0 row) :& row

-- generate a column and add it back to RecTshark
addHash :: FrameFiltered Packet -> Frame (Record '[PacketHash] )
addHash aframe =
  fmap (addHash')  (frame)
  where
    frame = fmap toHashablePacket (ffFrame aframe)
    addHash' row = Col (hash row) :& RNil


-- use zipFrames
-- just for testing
-- type Age = "age" :-> Int
-- type Weight = "weight" :-> Double
-- type Name = "name" :-> String

-- | Add a column to the head of a row.
-- frameCons :: (Functor f, KnownSymbol s)
--           => f a -> Rec f rs -> Rec f (s :-> a ': rs)
-- frameCons = (V.:&) . fmap Col
-- {-# INLINE frameCons #-}

-- testRec1 :: Record '[PacketHash, Name]
-- testRec1 = (Col 42) :& (Col "bob") :& RNil
-- :& (col 23) :&  (pure 75.2 )

type RecTsharkWithHash = '[PacketHash] ++ RecTshark

type TsharkMergedCols = '[PacketHash] ++ RecTshark ++ RecTsharkPrefixed

-- not a frame but hope it should be
type MergedPcap = [ Rec (Maybe :. ElField) TsharkMergedCols ]

-- | Merge of 2 frames
mergeTcpConnectionsFromKnownStreams ::
  FrameFiltered Packet -> FrameFiltered (Record RecTsharkPrefixed)
  -> MergedPcap
-- these are from host1 / host2
mergeTcpConnectionsFromKnownStreams aframe1 aframe2 =
  mergedFrame
  where
    -- we want an outerJoin , maybe with a status column like in panda
    -- outerJoin returns a list of [Rec (Maybe :. ElField) ors]
    mergedFrame = outerJoin @'[PacketHash] ( hframe1dest) ( hframe2)
    -- mergedFrame = innerJoin @'[PacketHash] ( hframe1) ( hframe2)
    -- mergedFrame = hframe1
    hframe1 = zipFrames (addHash aframe1) (ffFrame aframe1)
    hframe1dest = hframe1
    -- hframe1dest = addTcpDestinationsToFrame hframe1
    hframe2 = zipFrames (addHash aframe1) (ffFrame aframe2)
    -- hframe3 = toFrame [testRec1]
    -- newCol = retypeColumn @AbsTime @AbsTime2 (frameRow (ffFrame aFrame2) 0)
    -- processedFrame2 :: Frame (Record CsvHeader)
    -- , '("relTime", "relTime2", Double)
    -- processedFrame2 = fmap (retypeColumns @'[ '("absTime", "absTime2", Double)  ]) frame2
    -- processedFrame2 = fmap (retypeColumns @'[ '("absTime", "absTime2", Double)  ]) frame2
    -- processedFrame2 :: Frame Packet
    -- processedFrame2 = fmap (retypeColumn @AbsTime @TestAbsTime) frame2

-- TODO we need to reorder from host1 / host2 to client server



-- | Result of the merge of 2 pcaps
-- genExplicitRecord "" "RecTshark" mergedFields

-- gen


-- FrameMergedOriented
-- inspirted by convert_to_sender_receiver
-- TODO need to 
-- this is for a TCP frame
-- FrameMerged
-- for now ignore deal with frame directly rather than FrameFiltered
convertToSenderReceiver ::
  Frame (Rec (Maybe :. ElField) TsharkMergedCols)
  -> Frame (Record RecTshark)
convertToSenderReceiver oframe = do
  -- compare first packet time
  if delta > 0 then
    -- host1 is the client
    -- h1_role = Client
    -- filterFrame (
    -- TODO filter per destination
    -- then rename into sndTime, rcvTime
    -- fmap retype
    mempty
  else
    mempty

  where
    tframe = fmap recMaybe oframe
    jframe = toFrame $ catMaybes $ toList tframe
    firstRow = frameRow jframe 0
    -- instead of taking firstRow we should compare the minima in case there are retransmissions
    delta :: Double
    delta =  (firstRow ^. testAbsTime)
-- (absTime firstRow) -
    -- frame of something
    -- For instance
    -- renameTo :: ConnectionRole
    --   -> Bool -- ^ true if the sender
    --   -> Frame (Rec (Maybe :. ElField) TsharkMergedCols) -- ^ return frame rearranged
    -- -- or concat
    -- renameTo role isSender = sendFrame 
      -- TODO <> recvFrame
      where
        -- succ ?
        -- sendFrame = retypeColumn @AbsTime @SndTime (filterFrame (\x -> x ^. tcpDest == role) mframe)
        -- TODO use (succ role) instead
        -- recvFrame = retypeColumn @AbsTime @SndTime (filterFrame (\x -> x ^. tcpDest == role) mframe)

