module Net.Tcp.Stat
where

type Byte = Int

data TcpUnidirectionalStats = TcpUnidirectionalStats {
    -- sum of tcplen / should be the same for tcp/mptcp
    -- Include redundant packets contrary to '''
    throughputBytes :: Byte

    -- duration
    , tcpDuration :: Double

    -- For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    , tcpByteRange :: Int

    -- application data = goodput = useful bytes '''
    , mptcp_application_bytes:: Byte

    , throughput_contribution:: Double

    , goodput_contribution:: Double

    -- For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    , tcp_goodput :: Byte
    }
