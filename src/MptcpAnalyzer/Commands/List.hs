-- {-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE PackageImports           #-}

module MptcpAnalyzer.Commands.List
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Types
import "mptcp-pm" Net.Tcp (TcpFlag(..))
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.ArtificialFields
import Net.Tcp.Stats

import Prelude hiding (log)
import Options.Applicative
import Frames
import Control.Lens hiding (argument)
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Polysemy.Trace as P
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


piListTcpOpts ::  ParserInfo CommandArgs
piListTcpOpts = info (
   ArgsListTcpConnections <$> parserList <**> helper)
  ( progDesc "List subflows of an MPTCP connection"
  )
  where
    parserList = switch (long "detailed" <> help "detail connections")

-- piTcpSummaryOpts :: Member Command r => ParserInfo (Sem r CMD.RetCode)
-- piTcpSummaryOpts = info (
--    CMD.cmdTcpSummary <$> parserSummary <**> helper)
--   ( progDesc "Detail a specific TCP connection"
--   )

piTcpSummaryOpts :: ParserInfo CommandArgs
piTcpSummaryOpts = info (
   parserSummary <**> helper)
  ( progDesc "Detail a specific TCP connection"
  )


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
cmdListTcpConnections ::
  Members '[Log String, P.Trace, P.State MyState, Cache, Embed IO] r
  => Bool -- ^ detailed
  -> Sem r RetCode
cmdListTcpConnections listDetailed = do
    -- TODO this part should be extracted so that
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> do
        log ( "please load a pcap first" :: String)
        return CMD.Continue
      Just frame -> do
        let tcpStreams = getTcpStreams frame
        let streamIdList = if listDetailed then [] else tcpStreams
        -- log $ "Number of rows " ++ show (frameLength frame)
        P.trace $ "Number of TCP connections " ++ show (length tcpStreams)
        -- TODO use a trace there
        _ <- mapM (P.trace . describeFrame . buildTcpConnectionFromStreamId frame ) streamIdList
        return CMD.Continue
    where
      describeFrame = \case
        Left msg -> msg
        Right ff -> showConnection (ffCon ff)


{-| Display statistics for the connection:
throughput/goodput

detailed
-}
cmdTcpSummary :: Members '[Log String, P.Trace, P.State MyState, Cache, Embed IO] r
  => StreamId Tcp
  -> Bool
  -> Sem r RetCode
cmdTcpSummary streamId detailed = do
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> trace ("please load a pcap first" :: String) >> return CMD.Continue
      Just frame -> case buildTcpConnectionFromStreamId frame streamId of
        Left msg -> return $ CMD.Error msg
        Right aframe -> do
          -- let _tcpstreams = getTcpStreams frame
          P.trace $ showConnection (ffCon aframe)
          log $ "Number of rows " ++ show (frameLength frame)
          if detailed
          then
            trace $ showStats RoleServer
            -- P.trace $ showStats RoleClient
            -- P.trace ""
          else
            pure ()
          -- log $ "Number of SYN packets " ++ (fmap  )
          return CMD.Continue
          where
              filteredFrame = buildTcpConnectionFromStreamId frame streamId
              -- forwardStats = showStats RoleServer
              showStats direction = let
                  tcpStats = getTcpStats aframe direction
                in
                  showTcpStats tcpStats

showTcpStats :: TcpUnidirectionalStats -> String
showTcpStats s =
                  "- transferred " ++ ++ show (tusSndNext s - tusMinSeq s + 1 + tusReinjectedBytes s)  ++ " bytes "
                  ++ " over " ++ show (tusEndTime s - tusStartTime s) ++ "s"

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
cmdMptcpSummary :: Members '[Log String, P.State MyState, Cache, Embed IO] r
  => StreamId Tcp
  -> Bool
  -> Sem r RetCode
cmdMptcpSummary streamId detailed = do
  state <- P.get
  case view loadedFile state of
    Nothing -> trace ("please load a pcap first" :: String) >> return CMD.Continue
    Just frame -> case buildTcpConnectionFromStreamId frame streamId of
      Left msg -> return $ CMD.Error msg
      Right aframe -> do
        -- let _tcpstreams = getTcpStreams frame
        P.trace $ showConnection (ffCon aframe)
        log $ "Number of rows " ++ show (frameLength frame)
        if detailed
        then
          trace $ showStats RoleServer
          -- P.trace $ showStats RoleClient
          -- P.trace ""
        else
          pure ()

  where
    -- dadsa
    subflowStats = map ()

  -- for destination in args.dest:
  --   stats = mptcp_compute_throughput(
  --       self.data, args.mptcpstream,
  --       destination,
  --       False
  --   )


-- cmdTcpSummary :: Members '[Log String, P.State MyState, Cache, Embed IO] r => ParserSummary -> Sem r RetCode
-- cmdTcpSummary args = do
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
--             tcpCon = buildTcpConnectionFromStreamId frame (summaryTcpStreamId args)

