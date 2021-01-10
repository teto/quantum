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

-- TODO do a variant with an already filtered one
getTcpUnidirectionalStats :: PcapFrame -> StreamIdTcp -> ConnectionRole -> TcpUnidirectionalStats
getTcpUnidirectionalStats frame streamId = do
-- def tcp_get_stats(
--     rawdf,
--     tcpstreamid: TcpStreamId,
--     destination: ConnectionRoles,
--     mptcp=False
-- ) -> TcpUnidirectionalStats:
    -- '''
    -- Expects df to have tcpdest set
    -- '''
    log.debug("Getting TCP stats for stream %d", tcpstreamid)
    assert destination in ConnectionRoles, "destination is %r" % type(destination)

    df = rawdf[rawdf.tcpstream == tcpstreamid]
    if df.empty:
        raise MpTcpException("No packet with tcp.stream == %d" % tcpstreamid)

    df2 = df

    log.debug("df2 size = %d" % len(df2))
    log.debug("Looking at role %s" % destination)
    # assume it's already filtered ?
    sdf = df2[df2.tcpdest == destination]
    bytes_transferred = Byte(sdf["tcplen"].sum())
    assert bytes_transferred >= 0

    # -1 to account for SYN
    tcp_byte_range, seq_max, seq_min = transmitted_seq_range(sdf, "tcpseq")

    # print(sdf["abstime"].head())
    # print(dir(sdf["abstime"].dt))
    # print(sdf["abstime"].dt.end_time)
    times = sdf["abstime"]
    tcp_duration = times.iloc[-1] - times.iloc[0]
    # duration = sdf["abstime"].dt.end_time - sdf["abstime"].dt.start_time

    assert tcp_byte_range is not None

    return TcpUnidirectionalStats(
        tcpstreamid,
        tcp_duration=tcp_duration,
        throughput_bytes=bytes_transferred,
        # FIX convert to int because Byte does not support np.int64
        tcp_byte_range=Byte(tcp_byte_range)
    )
