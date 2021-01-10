module MptcpAnalyzer.Commands.ListMptcp
where



listMpTcpConnectionsCmd :: Members '[Log String, P.State MyState, Cache, Embed IO] r => ParserListSubflows -> Sem r RetCode
listMpTcpConnectionsCmd _args = do
    -- TODO this part should be extracted so that
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> do
        log ( "please load a pcap first" :: String)
        return CMD.Continue
      Just frame -> do
        let tcpStreams = getTcpStreams frame
        -- log $ "Number of rows " ++ show (frameLength frame)
        P.embed $ putStrLn $ "Number of TCP connections " ++ show (length tcpStreams)
        -- mapM (putStrLn . showTcpConnection <$> buildConnectionFromTcpStreamId frame ) tcpStreams
        -- >>
        return CMD.Continue
