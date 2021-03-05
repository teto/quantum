-- {-# LANGUAGE FlexibleContexts           #-}

module MptcpAnalyzer.Commands.List
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Types
import Net.Tcp (TcpConnection(..), TcpFlag(..))
import MptcpAnalyzer.Pcap

import Prelude hiding (log)
import Options.Applicative
import Frames
import Control.Lens hiding (argument)
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)
import Data.Either (fromRight)

import MptcpAnalyzer.Types

-- import qualified Pipes.Prelude as P
-- import Pipes (Producer, (>->))
-- import qualified Pipes.Prelude as P
-- import qualified Control.Foldl as L

-- for TcpConnection


parserSummary :: Parser CommandArgs
parserSummary = ArgsParserSummary <$> switch
          ( long "full"
         <> help "Print details for each subflow" )
      <*> argument readStreamId (
          metavar "STREAM_ID"
          <> help "Stream Id (tcp.stream)"
          -- TODO pass a default
          )


listTcpOpts ::  ParserInfo CommandArgs
listTcpOpts = info (
   ArgsListTcpConnections <$> parserList <**> helper)
  ( progDesc "List subflows of an MPTCP connection"
  )
  where
    parserList = switch (long "detailed" <> help "detail connections")

-- tcpSummaryOpts :: Member Command r => ParserInfo (Sem r CMD.RetCode)
-- tcpSummaryOpts = info (
--    CMD.tcpSummary <$> parserSummary <**> helper)
--   ( progDesc "Detail a specific TCP connection"
--   )

tcpSummaryOpts :: ParserInfo CommandArgs
tcpSummaryOpts = info (
   parserSummary <**> helper)
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
listTcpConnectionsCmd :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
listTcpConnectionsCmd args = do
    -- TODO this part should be extracted so that
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> do
        log ( "please load a pcap first" :: String)
        return CMD.Continue
      Just frame -> do
        let tcpStreams = getTcpStreams frame
        let streamIdList = if _listTcpDetailed args then [] else tcpStreams
        -- log $ "Number of rows " ++ show (frameLength frame)
        P.embed $ putStrLn $ "Number of TCP connections " ++ show (length tcpStreams)
        _ <- P.embed $ mapM (putStrLn . describeFrame . buildConnectionFromTcpStreamId frame ) streamIdList
        return CMD.Continue
    where
      describeFrame = \case
        Left msg -> msg
        Right ff -> showConnection (ffTcpCon ff)

{-| Display statistics for the connection:
throughput/goodput
-}
tcpSummary :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
tcpSummary args = do
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> log ("please load a pcap first" :: String) >> return CMD.Continue
      Just frame -> do
        let _tcpstreams = getTcpStreams frame
        log $ "Number of rows " ++ show (frameLength frame)
        case showConnection <$> ffTcpCon <$> filteredFrame of
          Left err -> log $ "error happened:" ++ err
          Right desc -> log desc
        -- log $ "Number of SYN packets " ++ (fmap  )
        >> return CMD.Continue
        where
            filteredFrame = buildConnectionFromTcpStreamId frame (summaryTcpStreamId args)

{-
mptcp stream 0 transferred 308.0 Bytes over 45.658558 sec(308.0 Bytes per second) towards Client.
tcpstream 0 transferred 308.0 Bytes out of 308.0 Bytes, accounting for 100.00%
tcpstream 2 transferred 0.0 Bytes out of 308.0 Bytes, accounting for 0.00%
tcpstream 6 transferred 0.0 Bytes out of 308.0 Bytes, accounting for 0.00%
mptcp stream 0 transferred 469.0 Bytes over 45.831181 sec(456.0 Bytes per second) towards Server.
tcpstream 0 transferred 460.0 Bytes out of 469.0 Bytes, accounting for 98.08%
tcpstream 2 transferred 9.0 Bytes out of 469.0 Bytes, accounting for 1.92%
tcpstream 4 transferred 0.0 Bytes out of 469.0 Bytes, accounting for 0.00%
tcpstream 6 transferred 0.0 Bytes out of 469.0 Bytes, accounting for 0.00%
-}
cmdMptcpSummary :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
cmdMptcpSummary args = do
  -- for destination in args.dest:
  --   stats = mptcp_compute_throughput(
  --       self.data, args.mptcpstream,
  --       destination,
  --       False
  --   )

  return CMD.Continue

-- tcpSummary :: Members '[Log String, P.State MyState, Cache, Embed IO] r => ParserSummary -> Sem r RetCode
-- tcpSummary args = do
--     state <- P.get
--     let loadedPcap = view loadedFile state
--     case loadedPcap of
--       Nothing -> log ("please load a pcap first" :: String) >> return CMD.Continue
--       Just frame -> do
--         let _tcpstreams = getTcpStreams frame
--         log $ "Number of rows " ++ show (frameLength frame)
--         case fmap showTcpConnection tcpCon of
--           Left err -> log $ "error happened:" ++ err
--           Right desc -> log desc
--         -- log $ "Number of SYN packets " ++ (fmap  )
--         >> return CMD.Continue
--         where
--             tcpCon = buildConnectionFromTcpStreamId frame (summaryTcpStreamId args)

-- listTcpConnectionsInFrame :: SomeFrame -> IO ()
-- listTcpConnectionsInFrame frame = do
--   putStrLn "Listing tcp connections"
--   let streamIds = getTcpStreams frame
--   mapM_ print streamIds

  -- L.fold L.minimum (view age <$> ms)
  -- L.fold
  -- putStrLn $ show $ rcast @'[TcpStream] $ frameRow frame 0
  -- let l =  L.fold L.nub (view tcpstream <$> frame)
-- listMptcpConnections :: SomeFrame -> MyStack IO ()
-- listMptcpConnections frame = do
--     return ()


