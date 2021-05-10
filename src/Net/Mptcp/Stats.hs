module Net.Mptcp.Stats
where

import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Types
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Frame
import MptcpAnalyzer.Stream
import Net.Tcp
import Net.Mptcp.Connection
import qualified Data.Map as Map


import qualified Control.Foldl as L
import Control.Lens hiding (argument)
import Data.Word (Word32, Word64)
import Data.Maybe (fromJust)
import qualified Frames as F
import qualified Data.Foldable as F
import Data.List (sortBy, sortOn)

-- | Useful to show DSN
data TcpSubflowUnidirectionalStats = TcpSubflowUnidirectionalStats {

  }

-- | Holds MPTCP statistics for one direction
data MptcpUnidirectionalStats = MptcpUnidirectionalStats {
  musApplicativeBytes :: Word64
  musSubflowStats :: [ TcpSubflowUnidirectionalStats ]
  }


data MptcpUnidirectionalStats = MptcpUnidirectionalStats {
  musApplicativeBytes :: Word64
  musSubflowStats :: [ TcpUnidirectionalStats ]
  }

    -- ''' application data = goodput = useful bytes '''
    -- ''' max(dsn)- min(dsn) - 1'''
    -- mptcp_application_bytes: Byte

    -- '''Total duration of the mptcp connection'''
    -- mptcp_duration: datetime.timedelta
    -- subflow_stats: List[TcpUnidirectionalStats]

    -- @property
    -- def mptcp_throughput_bytes(self) -> Byte:
    --     ''' sum of total bytes transferred '''
    --     return Byte(sum(map(lambda x: x.throughput_bytes, self.subflow_stats)))


-- mptcp_compute_throughput est bourrin il calcule tout d'un coup, je veux avoir une version qui marche iterativement
getMptcpStats :: FrameFiltered MptcpConnection Packet
  -> ConnectionRole
  -> TcpUnidirectionalStats
getMptcpStats aframe dest =
  MptcpUnidirectionalStats {
    -- tusThroughput = 0
    -- , tusStartPacketId = 0
    -- , tusEndPacketId = 0
    -- , tusStartTime = minTime
    -- , tusEndTime = maxTime
    -- -- TODO fill it
    -- , tusMinSeq = minSeq
    -- , tusSndUna = maxSeq -- TODO should be max of seen acks
    -- , tusSndNext = maxSeq
    -- , tusReinjectedBytes = 0
    -- , tusSnd = 0
    -- , tusCumulativeBytes = mempty
    -- , tusMinSeq = minSeq
    -- , tusMaxSeq = maxSeq
    -- , tusGoodput = 0
    -- , tusGoodput = (fromIntegral $ maxSeq-minSeq)/(tusEnd - tusStart)
  }
  where
    frame = ffFrame aframe
    -- these return Maybes
    minSeq = minimum (F.toList $ view tcpSeq <$> frame)
    maxSeq = maximum $ F.toList $ view tcpSeq <$> frame

    maxTime = maximum $ F.toList $ view relTime <$> frame
    minTime = minimum $ F.toList $ view relTime <$> frame

-- 
getMptcpGoodput :: MptcpUnidirectionalStats -> Double
getMptcpGoodput s = undefined


-- | return max - min across subflows
getMptcpStatsDuration :: MptcpUnidirectionalStats -> Double
getMptcpStatsDuration s = end - start
  where
    -- min of
    start = sortOn tusStartTime (musSubflowStats s)
    -- take the maximum
    end = sortOn tusStartTime (musSubflowStats s)
