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

import Prelude hiding (log)
import MptcpAnalyzer.Types
import Tshark.TH
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Types
-- for retypeColumn
import MptcpAnalyzer.Frames.Utils
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Map
-- (addTcpDestToFrame, StreamConnection)


import Frames as F
import Frames.CSV
import Frames.Joins
import Data.List (sortBy, sortOn, intersperse, intercalate)
import Data.Vinyl
import Data.Vinyl.TypeLevel
import Data.Vinyl.TypeLevel as V --(type (++), Snd)
import Data.Hashable
import GHC.TypeLits (KnownSymbol, Symbol)
import qualified Data.Vinyl as V
import Language.Haskell.TH (Name)
import Net.IP (IP)
import Net.Tcp
import Net.Mptcp
import Data.Word (Word8, Word16, Word32, Word64)
import Data.Maybe (catMaybes)
import Data.Foldable (toList)
import Control.Lens
import Frames.Melt          (RDeleteAll, ElemOf)
import Data.Either (fromRight)

import qualified Pipes as Pipes
import qualified Pipes.Prelude as Pipes
import qualified Data.Foldable as F
import Polysemy
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import qualified Polysemy.Embed as P

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
addHash :: StreamConnection a b => FrameFiltered a Packet -> Frame (Record '[PacketHash] )
addHash aframe =
  fmap (addHash')  (frame)
  where
    frame = fmap toHashablePacket (ffFrame aframe)
    addHash' row = Col (hash row) :& RNil


type MergedHostCols = PacketHash ': '[TcpDest] V.++ HostCols V.++ HostColsPrefixed

-- not a frame but hope it should be
type MergedPcap = [Rec (Maybe :. ElField) MergedHostCols]

-- liste de
mergedPcapToFrame :: MergedPcap -> (FrameRec MergedHostCols, MergedPcap)
mergedPcapToFrame mergedRes = let
  -- P.embed $ putStrLn $ "There are " ++ show (length justRecs) ++ " valid merged rows (out of " ++ show (length mergedRes) ++ " merged rows)"
  -- P.embed $ putStrLn $ (concat . showFields) (head justRecs)
    mbRecs = map recMaybe mergedRes
    justRecs = catMaybes mbRecs
  in
    (toFrame justRecs, [])


writeMergedPcap :: FilePath -> MergedPcap -> IO ()
writeMergedPcap outPath mergedPcap = do
  -- showReinjects frame =
    -- unlines (intercalate sep (columnHeaders (Proxy :: Proxy (Record rs))) : rows)
    writeFile outPath content
    where
      content = intercalate "," rows
      rows = Pipes.toList (F.mapM_ (Pipes.yield . show ) mergedPcap)



-- | Merge of 2 frames
mergeMptcpConnectionsFromKnownStreams ::
  (Members '[Log] r)
  => FrameFiltered MptcpConnection Packet
  -> FrameFiltered MptcpConnection Packet
  -> Sem r MergedPcap
mergeMptcpConnectionsFromKnownStreams (FrameTcp con1 frame1) (FrameTcp con2 frame2) = do
  let mappedSubflows = mapSubflows con1 con2
  Log.info $ "Mapped subflows" <> showMptcpSubflowMapping mappedSubflows
  -- mergedFrames = map
  mergedFrames <- mapM  mergeSubflow mappedSubflows
  return $ mconcat mergedFrames
  where
    --
    -- mergeSubflow :: (MptcpSubflow, [(MptcpSubflow, Int)]) -> MergedPcap
    mergeSubflow (sf1, scores) = do
      Log.debug $ "Merging pcap1 stream" <> tshow streamId1 <> " and " <> tshow streamId2
      return $ mergeTcpConnectionsFromKnownStreams' aframe1 aframe2
      where
        streamId1 = conTcpStreamId $ sfConn sf1
        streamId2 = conTcpStreamId $ sfConn $ fst (head scores)
        aframe1 = fromRight undefined (buildFrameFromStreamId frame1 streamId1)
        aframe2 = fromRight undefined (buildFrameFromStreamId frame2 (streamId2))


mergeMptcpConnectionsFromKnownStreams' ::
  FrameFiltered MptcpConnection Packet
  -> FrameFiltered MptcpConnection Packet
  -> MergedPcap
mergeMptcpConnectionsFromKnownStreams' (FrameTcp con1 frame1) (FrameTcp con2 frame2) = let
  -- first we need to map subflow to oneanother
  -- map mpconSubflows
    mappedSubflows = mapSubflows con1 con2
    mergedFrames = map mergeSubflow mappedSubflows

    -- aframeSf1 = buildFrameFromStreamId frame1 (conTcpStreamId $ sfConn con1) 
    -- aframeSf1 = buildFrameFromStreamId frame2 (conTcpStreamId $ sfConn con1) 
    -- sf1 = buildTcpConnectionFromStreamId (

    -- :: MptcpSubflow ->
    mergeSubflow :: (MptcpSubflow, [(MptcpSubflow, Int)]) -> MergedPcap
    mergeSubflow (sf1, scores) = mergeTcpConnectionsFromKnownStreams' aframe1 aframe2
      where
        aframe1 = fromRight undefined (buildFrameFromStreamId frame1 (conTcpStreamId $ sfConn sf1) )
        aframe2 = fromRight undefined (buildFrameFromStreamId frame2 (conTcpStreamId $ sfConn $ fst (head scores ) ))
                                    -- (FrameFiltered (sfConn sf) frame1)
                                    -- (FrameFiltered (sfConn sf) frame2)
  in
    mconcat mergedFrames

mergeTcpConnectionsFromKnownStreams ::
  (Members '[Log, P.Embed IO] r)
  => FrameFiltered TcpConnection Packet
  -> FrameFiltered TcpConnection Packet
  -> Sem r MergedPcap
-- these are from host1 / host2
mergeTcpConnectionsFromKnownStreams aframe1 aframe2 = do
  embed $ writeDSV defaultParserOptions "merge-tcp-debug-1.csv" hframe1
  embed $ writeDSV defaultParserOptions "merge-tcp-debug-2.csv" hframe2

  return mergedFrame
  where
    -- we want an outerJoin , maybe with a status column like in panda
    -- outerJoin returns a list of [Rec (Maybe :. ElField) ors]
    mergedFrame = outerJoin @'[PacketHash] (hframe1dest) processedFrame2

    frame1withDest = addTcpDestToFrame (ffFrame aframe1) (ffCon aframe1)

    hframe1 = zipFrames (addHash aframe1) frame1withDest
    hframe1dest = hframe1
    -- hframe1dest = addTcpDestinationsToAFrame hframe1
    hframe2 :: Frame (Record ('[PacketHash] ++ HostColsPrefixed))
    hframe2 = zipFrames (addHash aframe2) host2_frame

    host2_frame = convertToHost2Cols (ffFrame aframe2)
    processedFrame2 = hframe2


-- | Merge of 2 frames
-- inspired by merge_tcp_dataframes_known_streams
mergeTcpConnectionsFromKnownStreams' ::
  FrameFiltered TcpConnection Packet
  -> FrameFiltered TcpConnection Packet
  -> MergedPcap
-- these are from host1 / host2
mergeTcpConnectionsFromKnownStreams' aframe1 aframe2 =
  mergedFrame
  where
    -- (Record HostColsPrefixed)
    -- we want an outerJoin , maybe with a status column like in panda
    -- outerJoin returns a list of [Rec (Maybe :. ElField) ors]
    mergedFrame = outerJoin @'[PacketHash] (hframe1dest) processedFrame2

    frame1withDest = addTcpDestToFrame (ffFrame aframe1) (ffCon aframe1)

    hframe1 = zipFrames (addHash aframe1) frame1withDest
    hframe1dest = hframe1
    -- hframe1dest = addTcpDestinationsToAFrame hframe1
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
--
-- In the mergedpcap we have mapped packets from 2 hosts. We then have to decide
-- between the 2 hosts which one acted as a client and which one as the server.
--
-- @param j
--  Convert dataframe from  X_HOST1 ': X_HOST2 to X_SENDER ': X_RECEIVER
--  Each mapping PACKET_HOST_1 <-> PACKET_HOST_2 is associated with its destination Server/Client
--  We thus need to find out which host acted as a Client or Server;
--  then we can select packets whose destination is the Server
--  and for those packets set the Sender to HOST1 or HOST2
--
-- 1/ we compare the abstime of the first packet (TODO we could select the role instead ?!)
convertToSenderReceiver ::
  MergedPcap
  -> FrameRec SenderReceiverCols
convertToSenderReceiver oframe = do
  -- compare first packet time
  if delta > 0 then
    -- host1 is the client
    -- then rename into sndTime, rcvTime
    -- TODO
    -- convertHost1AsClient
    setHost1AsSenderForDest RoleServer
    <> setHost2AsSenderForDest  RoleClient
  else
    -- convertHost1AsServer
    setHost1AsSenderForDest RoleServer
      <> setHost2AsSenderForDest  RoleClient

  where
    -- tframe :: [Maybe MergedHostCols]
    tframe :: [Maybe (Record MergedHostCols)]
    tframe = fmap recMaybe oframe
    jframe :: FrameRec MergedHostCols
    jframe = toFrame $ catMaybes $ toList tframe
    firstRow = frameRow jframe 0

    --
    -- convertToSenderReceiver' :: ConnectionRole -> ConnectionRole
    -- convertToSenderReceiver' h1role

    -- convertHost1AsClient = 

    -- instead of taking firstRow we should compare the minima in case there are retransmissions
    delta :: Double
    delta =  (firstRow ^. testAbsTime) - (firstRow ^. absTime)

    selectDest :: ConnectionRole -> FrameRec MergedHostCols
    selectDest dest = (filterFrame (\x -> x ^. tcpDest == dest) jframe)

    -- em fait le retype va ajouter la colonne a la fin seulement
    -- zipFrames
    setHost1AsSenderForDest, setHost2AsSenderForDest  :: ConnectionRole -> FrameRec SenderReceiverCols
    setHost1AsSenderForDest dest = fmap convertToSender (selectDest dest)

    -- (if h1role == RoleClient then RoleServer else RoleClient))
    setHost2AsSenderForDest  dest = fmap convertToReceiver (selectDest dest)

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


-- | Add a One-Way-Delay column to the results
-- addOWD :: Frame (Record RecSenderReceiver) -> Frame (Record '[OWD] ++ RecSenderReceiver)
-- addOWD = fmap addOWD'
--   where
--     addOWD' = (rcvAbsTime x - sndAbsTime x)
