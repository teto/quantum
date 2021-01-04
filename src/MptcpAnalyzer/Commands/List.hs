{-# LANGUAGE FlexibleContexts           #-}

module MptcpAnalyzer.Commands.List
where

import Prelude hiding (log)
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.Utils as CMD
import MptcpAnalyzer.Definitions
import Net.Tcp (TcpConnection(..), TcpFlag(..))
import Options.Applicative
import MptcpAnalyzer.Pcap
import Frames
import Control.Lens hiding (argument)
import Polysemy (Member, Members, Sem, Embed)
-- import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)

-- import qualified Pipes.Prelude as P
import Pipes (Producer, (>->))
import qualified Pipes.Prelude as P
import qualified Control.Foldl as L

-- for TcpConnection
-- import Net.Tcp



-- This 

-- |TODO pass the loaded pcap to have a complete filterWith
-- listSubflowParser = 

parserSubflow :: Parser ParserListSubflows
parserSubflow = ParserListSubflows <$> switch
          ( long "full"
         <> help "Print details for each subflow" )
      <*> argument readStreamId (
          metavar "STREAM_ID"
          <> help "Stream Id (tcp.stream)"
          -- TODO pass a default
          )

readStreamId :: ReadM (StreamId Tcp)
readStreamId = eitherReader $ \arg -> case reads arg of
  [(r, "")] -> return $ StreamId r
  _ -> Left $ "cannot parse value `" ++ arg ++ "`"

listTcpOpts :: Member Command r => ParserInfo (Sem r CMD.RetCode)
listTcpOpts = info (
   CMD.listTcpConnections <$> parserSubflow <**> helper)
  ( progDesc "List subflows of an MPTCP connection"
  )

tcpSummaryOpts :: Member Command r => ParserInfo (Sem r CMD.RetCode)
tcpSummaryOpts = info (
   CMD.tcpSummary <$> parserSubflow <**> helper)
  ( progDesc "Detail a specific TCP connection"
  )

-- listTcpConnections :: [TcpConnection] -> Text
-- listTcpConnections conns =
--         streams = self.data.groupby("tcpstream")
--         (show len connections) ++ " tcp connection(s)" ++ map (\
--         where
          -- for tcpstream, group in streams:
          --     con = TcpConnection.build_from_dataframe(self.data, tcpstream)
          --     self.poutput(str(con))
-- checkIfLoaded :: CMD.CommandConstraint m => [String] -> m CMD.RetCode
-- checkIfLoaded = 
    -- putStrLn "not loaded"

    -- Search for SYN flags
    -- filterFrame
    -- Producer Income m ()
    -- testField = filter
    --           ((> 50) . rgetField @Val))
    --           (testMelt testRec1)
    -- L.genericLength
    -- filterFrame :: RecVec rs => (Record rs -> Bool) -> FrameRec rs -> FrameRec rs

buildConnectionFromRow :: Record Packet -> TcpConnection
buildConnectionFromRow r = 
  TcpConnection {
    srcIp = r ^. ipSource
    , dstIp = r ^. ipDest
    , srcPort = r ^. tcpSrcPort
    , dstPort = r ^. tcpDstPort
    , priority = Nothing  -- for now
    , localId = 0
    , remoteId = 0
    , subflowInterface = Nothing
  }

-- | Tcp connection
-- TcpConnection
buildConnectionFromTcpStreamId :: PcapFrame -> StreamId Tcp -> Either String TcpConnection
buildConnectionFromTcpStreamId frame (StreamId streamId) = 
    -- Right $ frameLength synPackets
    if frameLength synPackets < 1 then
      Left "No packet with any SYN flag for tcpstream " ++ show streamId
    else
      buildConnectionFromRow $ head synPackets
    where
      streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId) frame
      -- suppose tcpflags is a list of flags, check if it is in the list
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
        -- where
          -- syns = np.bitwise_and(df['tcpflags'], TcpFlags.SYN)
          -- filterSyn flags = elem TcpFlagSyn flags
        --       fromStreamId = (== streamId) . view tcpStream

{-| Show a list of all connections
8 tcp connection(s)
  tcp.stream 0: 10.0.0.1:33782 -> 10.0.0.2:05201
  tcp.stream 1: 10.0.0.1:33784 -> 10.0.0.2:05201
  tcp.stream 2: 10.0.0.1:54595 -> 11.0.0.2:05201
  tcp.stream 3: 10.0.0.1:57491 -> 11.0.0.2:05201
  tcp.stream 4: 11.0.0.1:59555 -> 11.0.0.2:05201
  tcp.stream 5: 11.0.0.1:50077 -> 11.0.0.2:05201
  tcp.stream 6: 11.0.0.1:35589 -> 10.0.0.2:05201
  tcp.stream 7: 11.0.0.1:50007 -> 10.0.0.2:05201
-}
listTcpConnections :: Members [Log String, P.State MyState, Cache, Embed IO] r => ParserListSubflows -> Sem r RetCode
listTcpConnections _args = do
    -- TODO this part should be extracted so that
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> log "please load a pcap first" >> return CMD.Continue
      Just frame -> do
        let tcpStreams = getTcpStreams frame
        log $ "Number of rows " ++ show (frameLength frame)
        log $ "Number of TCP connections " ++ show (length tcpStreams)
        >> return CMD.Continue

{-| Display statistics for the connection:
throughput/goodput
-}
tcpSummary :: Members [Log String, P.State MyState, Cache, Embed IO] r => ParserListSubflows -> Sem r RetCode
tcpSummary args = do
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> log "please load a pcap first" >> return CMD.Continue
      Just frame -> do
        let _tcpstreams = getTcpStreams frame
        log $ "Number of rows " ++ show (frameLength frame)
        log $ "Number of SYN paclets " ++ show tcpCon
        >> return CMD.Continue
        where
            tcpCon = buildConnectionFromTcpStreamId frame (tcpStreamId args)


-- listTcpConnectionsInFrame :: PcapFrame -> IO ()
-- listTcpConnectionsInFrame frame = do
--   putStrLn "Listing tcp connections"
--   let streamIds = getTcpStreams frame
--   mapM_ print streamIds

  -- L.fold L.minimum (view age <$> ms)
  -- L.fold
  -- putStrLn $ show $ rcast @'[TcpStream] $ frameRow frame 0
  -- let l =  L.fold L.nub (view tcpstream <$> frame)
-- listMptcpConnections :: PcapFrame -> MyStack IO ()
-- listMptcpConnections frame = do
--     return ()


