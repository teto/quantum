module Net.Tcp.Stats
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Frame

import qualified Control.Foldl as L
import Control.Lens hiding (argument)
import Data.Word (Word32)
import Data.Maybe (fromJust)
import qualified Frames as F
import qualified Data.Foldable as F

type Byte = Int

-- tus = tcp Unidrectional Stats
data TcpUnidirectionalStats = TcpUnidirectionalStats {
    -- sum of tcplen / should be the same for tcp/mptcp
    -- Include redundant packets contrary to '''
    tusThroughput :: Byte

    -- duration
    -- , tusDuration :: Double
    , tusStart :: Double
    , tusEnd :: Double

    -- For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    , tusMinSeq :: Word32
    , tusMaxSeq :: Word32

    -- application data = goodput = useful bytes '''
    -- TODO move to its own ? / Maybe
    -- , mptcp_application_bytes :: Byte
    -- , tusThroughputContribution :: Double
    -- , tusGoodputContribution :: Double

    -- TODO this should be updated
    -- For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    , tusGoodput :: Byte
    }

data MptcpUnidirectionalStats = MptcpUnidirectionalStats {
    musThroughputContribution :: Double
    , musGoodputContribution :: Double
}


-- TODO should be able to update an initial one
--
getTcpStats :: FrameFiltered Packet -> ConnectionRole -> TcpUnidirectionalStats
getTcpStats aframe dest =
  TcpUnidirectionalStats {
    tusThroughput = 0
    , tusStart = minTime
    , tusEnd = maxTime
    , tusMinSeq = minSeq
    , tusMaxSeq = maxSeq
    , tusGoodput = 0
    -- , tusGoodput = (fromIntegral $ maxSeq-minSeq)/(tusEnd - tusStart)
  }
  where
    frame = ffFrame aframe
    -- these return Maybes
    minSeq = minimum (F.toList $ view tcpSeq <$> frame)
    maxSeq = maximum $ F.toList $ view tcpSeq <$> frame

    maxTime = maximum $ F.toList $ view relTime <$> frame
    minTime = minimum $ F.toList $ view relTime <$> frame

    -- duration = maxTime - minTime

-- No instance for (Ord (Frames.Frame.Frame GHC.Word.Word32))
-- instance Ord a => Ord (Frame a)
-- def transmitted_seq_range(df, seq_name):
--     '''
--     test
--     '''
--     log.debug("Computing byte range for sequence field %s", seq_name)

--     sorted_seq = df.dropna(subset=[seq_name]).sort_values(by=seq_name)
--     log.log(mp.TRACE, "sorted_seq %s", sorted_seq)

--     seq_min = sorted_seq.loc[sorted_seq.first_valid_index(), seq_name]
--     last_valid_index = sorted_seq.last_valid_index()
--     seq_max = sorted_seq.loc[last_valid_index, seq_name] \
--         + sorted_seq.loc[last_valid_index, "tcplen"]

--     # -1 because of SYN
--     # seq_range = seq_max - seq_min - 1
--     seq_range = seq_max - seq_min - 1

--     msg = "seq_range ({}) = {} (seq_max) - {} (seq_min) - 1"
--     log.log(mp.TRACE, msg.format(seq_range, seq_max, seq_min))
 
--     return seq_range, seq_max, seq_min

-- TODO do a variant with an already filtered one
-- getTcpUnidirectionalStats :: SomeFrameF Tcp ConnectionRole ->  -> TcpUnidirectionalStats
-- getTcpUnidirectionalStats frame streamId = do

-- getTcpUnidirectionalStats :: SomeFrame -> StreamIdTcp -> ConnectionRole -> TcpUnidirectionalStats
-- getTcpUnidirectionalStats frame streamId role = TcpUnidirectionalStats 0 0 0 0 0 0 0

  -- where
  --   packetStreams = filterStreamPackets frame streamId (Just role)
    -- log.debug("Getting TCP stats for stream %d", tcpstreamid)
    -- assert destination in ConnectionRoles, "destination is %r" % type(destination)

    -- df = rawdf[rawdf.tcpstream == tcpstreamid]
    -- if df.empty:
    --     raise MpTcpException("No packet with tcp.stream == %d" % tcpstreamid)

    -- df2 = df

    -- log.debug("df2 size = %d" % len(df2))
    -- log.debug("Looking at role %s" % destination)
    -- # assume it's already filtered ?
    -- sdf = df2[df2.tcpdest == destination]
    -- bytes_transferred = Byte(sdf["tcplen"].sum())
    -- assert bytes_transferred >= 0

    -- # -1 to account for SYN
    -- tcp_byte_range, seq_max, seq_min = transmitted_seq_range(sdf, "tcpseq")

    -- # print(sdf["abstime"].head())
    -- # print(dir(sdf["abstime"].dt))
    -- # print(sdf["abstime"].dt.end_time)
    -- times = sdf["abstime"]
    -- tcp_duration = times.iloc[-1] - times.iloc[0]
    -- # duration = sdf["abstime"].dt.end_time - sdf["abstime"].dt.start_time

    -- assert tcp_byte_range is not None

    -- return TcpUnidirectionalStats(
    --     tcpstreamid,
    --     tcp_duration=tcp_duration,
    --     throughput_bytes=bytes_transferred,
    --     # FIX convert to int because Byte does not support np.int64
    --     tcp_byte_range=Byte(tcp_byte_range)
    -- )
