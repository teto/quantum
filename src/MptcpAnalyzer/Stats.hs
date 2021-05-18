module MptcpAnalyzer.Stats
where

import Net.Tcp
import Net.Mptcp
import MptcpAnalyzer.Frame
import Tshark.Fields
import MptcpAnalyzer.Types
import MptcpAnalyzer.ArtificialFields


import Frames
import qualified Frames as F
import qualified Frames.InCore as F
import qualified Data.Foldable as F
import Control.Lens hiding (argument)
import Data.Either (fromRight)
import MptcpAnalyzer.Pcap
import Data.Set (toList)
import Data.Maybe (catMaybes)
import Data.Word (Word64)

-- TODO should be able to update an initial one
-- type Packet = Record HostCols

-- ⊆
getTcpStats ::
  (TcpSeq F.∈ rs, TcpDest F.∈ rs, F.RecVec rs, RelTime F.∈ rs)
  => FrameFiltered TcpConnection (F.Record rs)
  -> ConnectionRole -> TcpUnidirectionalStats
getTcpStats aframe dest =
  TcpUnidirectionalStats {
    tusThroughput = 0
    , tusStartPacketId = 0
    , tusEndPacketId = 0
    , tusStartTime = minTime
    , tusEndTime = maxTime
    -- TODO fill it
    , tusMinSeq = minSeq
    , tusSndUna = maxSeq -- TODO should be max of seen acks
    , tusSndNext = maxSeq
    , tusReinjectedBytes = 0
    -- , tusSnd = 0
    -- , tusCumulativeBytes = mempty
    -- , tusMinSeq = minSeq
    -- , tusMaxSeq = maxSeq
    -- , tusGoodput = 0
    -- , tusGoodput = (fromIntegral $ maxSeq-minSeq)/(tusEnd - tusStart)
  }
  where
    -- TODO filtrer par direction
    frame = F.filterFrame (\x -> x ^. tcpDest == dest) (ffFrame aframe)
    -- streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId) frame

    -- these return Maybes
    minSeq = minimum (F.toList $ view tcpSeq <$> frame)
    maxSeq = maximum $ F.toList $ view tcpSeq <$> frame

    maxTime = maximum $ F.toList $ view relTime <$> frame
    minTime = minimum $ F.toList $ view relTime <$> frame

-- | TcpSubflowUnidirectionalStats
getSubflowStats ::
  (TcpSeq F.∈ rs, F.RecVec rs, RelTime F.∈ rs
    , IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs, TcpStream ∈ rs
  -- , TcpDest F.∈ rs
  )
  => FrameFiltered MptcpSubflow (F.Record rs) -> ConnectionRole -> TcpSubflowUnidirectionalStats
getSubflowStats aframe role = TcpSubflowUnidirectionalStats {
      tssStats = getTcpStats (addTcpDestinationsToAFrame aframe') role
    }
    where
      aframe' = FrameTcp (sfConn $ ffCon aframe) (ffFrame aframe)


-- | TODO check boundaries etc
getSeqRange :: Num a => a -> a
  -> a
  -- -> (a, a, a)
-- getSeqRange maxSeq minSeq = (maxSeq - minSeq + 1, maxSeq, minSeq)
getSeqRange maxSeq minSeq = maxSeq - minSeq + 1

-- mptcp_compute_throughput est bourrin il calcule tout d'un coup, je veux avoir une version qui marche iterativement
getMptcpStats ::
  (
   -- TcpDest F.∈ rs
  MptcpDsn F.∈ rs, TcpSeq F.∈ rs, IpDest F.∈ rs, IpSource F.∈ rs
  , TcpDestPort F.∈ rs, MptcpRecvToken F.∈ rs
  , TcpFlags F.∈ rs, TcpSrcPort F.∈ rs, TcpStream F.∈ rs, RelTime F.∈ rs
  , rs F.⊆ HostCols
  , F.RecVec rs
  )
  => FrameFiltered MptcpConnection (F.Record rs)
  -> ConnectionRole
  -> MptcpUnidirectionalStats
getMptcpStats (FrameTcp mptcpConn frame) dest =
  MptcpUnidirectionalStats {
    musDirection = dest
    , musApplicativeBytes = getSeqRange maxDsn minDsn
    , musMaxDsn = maxDsn
    , musMinDsn = minDsn
    , musSubflowStats = map (getStats dest)  (toList $ mpconSubflows $ mptcpConn)
  }
  where
    -- buildTcpConnectionFromStreamId :: SomeFrame -> StreamId Tcp -> Either String (FrameFiltered TcpConnection Packet)
    -- traverse a set
    getStats role sf = let
        sfFrame = fromRight (error "could not build sfFrame") (buildSubflowFromTcpStreamId frame (conTcpStreamId $ sfConn sf))
        -- sfFrame' = addTcpDestinationsToAFrame sfFrame
      in
        getSubflowStats sfFrame role

    -- frame = addTcpDestToFrame $ ffFrame aframe
    -- these return Maybes
    minSeq = minimum (F.toList $ view tcpSeq <$> frame)
    maxSeq = maximum $ F.toList $ view tcpSeq <$> frame

    maxTime = maximum $ F.toList $ view relTime <$> frame
    minTime = minimum $ F.toList $ view relTime <$> frame

    -- dsn_range, dsn_max, dsn_min = transmitted_seq_range(df, "dsn")
    -- mbRecs = map recMaybe mergedRes
    -- justRecs = catMaybes mbRecs
  -- in
    -- (toFrame justRecs, [])

    dsns = catMaybes $ F.toList $ view mptcpDsn <$> frame

    -- mergedPcapToFrame
    maxDsn, minDsn :: Word64
    maxDsn = maximum dsns

    minDsn = minimum dsns

