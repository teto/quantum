{- Merge 2 dataframes

-}
{-# LANGUAGE TypeApplications             #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE PolyKinds             #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# OPTIONS_GHC -O0 #-}
module MptcpAnalyzer.Merge
where

import MptcpAnalyzer.Types
import Tshark.TH
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Types
-- for retypeColumn
import MptcpAnalyzer.Frames.Utils
import MptcpAnalyzer.Pcap (addTcpDestToFrame)


import Frames as F
import Frames.Joins
import Data.Vinyl
import Data.Vinyl.TypeLevel
import Data.Vinyl.TypeLevel as V --(type (++), Snd)
import Data.Hashable
import GHC.TypeLits (KnownSymbol, Symbol)
import qualified Data.Vinyl as V
import Language.Haskell.TH (Name)
import Net.IP (IP)
import Data.Word (Word8, Word16, Word32, Word64)
import Data.Maybe (catMaybes)
import Data.Foldable (toList)
import Control.Lens
import Frames.Melt          (RDeleteAll, ElemOf)

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
toHashablePacket :: Record HostCols -> Record HashablePart
toHashablePacket = rcast

-- instance Hashable (Rec ElField a) where

-- -- TODO should generate a column and add it back to HostCols
-- -- type FieldRec = Rec ElField
-- addHash :: FrameFiltered Packet -> Frame (Record (PacketHash ': HashablePart))
-- addHash aframe =
--   fmap (addHash')  ( frame)
--   where
--     frame = fmap toHashablePacket (ffFrame aframe)
--     addHash' row = Col (hashWithSalt 0 row) :& row

-- generate a column and add it back to HostCols
addHash :: FrameFiltered Packet -> Frame (Record '[PacketHash] )
addHash aframe =
  fmap (addHash')  (frame)
  where
    frame = fmap toHashablePacket (ffFrame aframe)
    addHash' row = Col (hash row) :& RNil


-- type MergedHostCols = PacketHash ': TcpDest ': HostCols ++ HostColsPrefixed
type MergedHostCols = PacketHash ': '[TcpDest] V.++ HostCols V.++ HostColsPrefixed

-- not a frame but hope it should be
type MergedPcap = [Rec (Maybe :. ElField) MergedHostCols]

-- | Merge of 2 frames
mergeTcpConnectionsFromKnownStreams ::
  FrameFiltered Packet
  -> FrameFiltered Packet
  -> MergedPcap
-- these are from host1 / host2
mergeTcpConnectionsFromKnownStreams aframe1 aframe2 =
  mergedFrame
  where
    -- (Record HostColsPrefixed)
    -- we want an outerJoin , maybe with a status column like in panda
    -- outerJoin returns a list of [Rec (Maybe :. ElField) ors]
    mergedFrame = outerJoin @'[PacketHash] (hframe1dest) processedFrame2

    frame1withDest = addTcpDestToFrame (ffFrame aframe1) (ffCon aframe1)

    hframe1 = zipFrames (addHash aframe1) frame1withDest
    hframe1dest = hframe1
    -- hframe1dest = addTcpDestinationsToFrame hframe1
    hframe2 :: Frame (Record ('[PacketHash] ++ HostColsPrefixed))
    hframe2 = zipFrames (addHash aframe2) host2_frame

    host2_frame = convertToHost2Cols (ffFrame aframe2)
    processedFrame2 = hframe2

-- | Result of the merge of 2 pcaps
-- genExplicitRecord "" "HostCols" mergedFields

-- gen https://hackage.haskell.org/package/vinyl-0.13.1/docs/Data-Vinyl-Derived.html
convertToHost2Cols :: FrameRec HostCols -> FrameRec HostColsPrefixed
convertToHost2Cols frame = fmap convertCols' frame
  where
    convertCols' :: Record HostCols -> Record HostColsPrefixed
    convertCols' = withNames . stripNames
    -- if you need a review on a specific patch, let us know
    -- stripNames r
    -- convertCols' r = F.rcast @HostColsPrefixed (retypeColumns @'[ '("fakePacketId", "fake_fakePacketId", Word64), '("fakeInterfaceName", "fake_fakeInterfaceName", Text) ] r)

-- convertCols :: Record a -> Record b
-- convertCols = withNames . stripNames 

-- TODO and then we should compute a owd
-- , RcvAbsTime
-- type SenderReceiverCols =  '[SndPacketId, RcvPacketId, SndAbsTime, RcvAbsTime, TcpDest]
-- TODO il nous faut le hash + la dest
type SenderReceiverCols =  TcpDest ': SenderCols V.++ ReceiverCols



-- FrameMergedOriented
-- inspirted by convert_to_sender_receiver
-- TODO this should be for a TCP frame
-- for now ignore deal with frame directly rather than FrameFiltered
convertToSenderReceiver ::
  MergedPcap
  -> FrameRec SenderReceiverCols
convertToSenderReceiver oframe = do
  -- compare first packet time
  if delta > 0 then
    -- host1 is the client
    -- then rename into sndTime, rcvTime
    -- TODO
    sendFrame RoleClient
      -- <> recvFrame RoleServer
  else
    sendFrame RoleServer
      -- <> recvFrame RoleClient

  where
    -- tframe :: [Maybe MergedHostCols]
    tframe :: [Maybe (Record MergedHostCols)]
    tframe = fmap recMaybe oframe
    jframe :: FrameRec MergedHostCols
    jframe = toFrame $ catMaybes $ toList tframe
    firstRow = frameRow jframe 0
    -- instead of taking firstRow we should compare the minima in case there are retransmissions
    delta :: Double
    delta =  (firstRow ^. testAbsTime)

    totoFrame :: ConnectionRole -> FrameRec MergedHostCols
    totoFrame h1role = (filterFrame (\x -> x ^. tcpDest == h1role) jframe)

    -- em fait le retype va ajouter la colonne a la fin seulement
    -- zipFrames
    sendFrame, recvFrame :: ConnectionRole -> FrameRec SenderReceiverCols
    sendFrame h1role = fmap convertToSender (totoFrame h1role)

    recvFrame h1role = fmap convertToReceiver (totoFrame (if h1role == RoleClient then RoleServer else RoleClient))

    convertToSender, convertToReceiver :: Record MergedHostCols -> Record SenderReceiverCols
    convertToSender r = let
        -- TODO add tcpDest
        senderCols :: Record SenderCols
        senderCols = (withNames . stripNames . F.rcast @HostCols) r
        receiverCols :: Record ReceiverCols
        receiverCols = (withNames . stripNames . F.rcast @HostColsPrefixed) r
      in
        (rget @TcpDest r) :& (rappend senderCols receiverCols)

    convertToReceiver r = let
        senderCols :: Record SenderCols
        senderCols = (withNames . stripNames . F.rcast @HostColsPrefixed) r
        receiverCols :: Record ReceiverCols
        receiverCols = (withNames . stripNames . F.rcast @HostCols) r
      in
        (rget @TcpDest r) :& (rappend senderCols receiverCols)
        -- convert ("first host") to sender/receiver
        -- TODO this could be improved


          -- F.rcast @SenderReceiverCols ((
          --   -- retypeColumns @'[ '("absTime", "snd_absTime", Double), '("test_absTime", "rcv_absTime", Double) ] r)
          --   retypeColumn @PacketId @SndPacketId
          --   . retypeColumn @TestPacketId @RcvPacketId
          --   . retypeColumn @AbsTime @SndAbsTime
          --   . retypeColumn @TestAbsTime @RcvAbsTime
          --   . retypeColumn @IpSource @SndIpSource
          --   . retypeColumn @IpDest @SndIpDest
          --   ) r)



-- | Add a One-Way-Delay column to the results
-- addOWD :: Frame (Record RecSenderReceiver) -> Frame (Record '[OWD] ++ RecSenderReceiver)
-- addOWD = fmap addOWD'
--   where
--     addOWD' = (rcvAbsTime x - sndAbsTime x)
