{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PackageImports #-}
module MptcpAnalyzer.Commands.ListMptcp
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.List as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types

-- import Net.Mptcp.Types (MptcpConnection(..), MptcpSubflow, showMptcpConnection)

import Net.Tcp (TcpConnection(..), TcpFlag(..), showTcpConnection)
import Prelude hiding (log)
import Options.Applicative
import Frames
import Control.Lens hiding (argument)
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)
import Data.Word (Word8, Word16, Word32, Word64)
import qualified Control.Foldl as L
import qualified Data.Set as Set
import qualified Pipes.Prelude as PP
import Data.Maybe (fromJust, catMaybes)
import Data.Either (fromRight)

listMpTcpOpts :: ParserInfo CommandArgs
listMpTcpOpts = info (
    parserList <**> helper)
  ( progDesc "List MPTCP connections"
  )
  where
    parserList = ArgsListMpTcpConnections <$> switch ( long "detailed" <> help "detail connections")

listMptcpSubflowOpts :: ParserInfo CommandArgs
listMptcpSubflowOpts = info (
    parserList <**> helper)
  ( progDesc "List MPTCP connections"
  )
  where
    parserList = ArgsListSubflows <$> switch ( long "detailed" <> help "detail connections")


listMptcpReinjectionsOpts :: ParserInfo CommandArgs
listMptcpReinjectionsOpts = info (
    parserList <**> helper)
  ( progDesc "List MPTCP reinjections"
  )
  where
    parserList = ArgsListSubflows <$> switch ( long "detailed" <> help "detail connections")


-- keepMptcpPackets :: SomeFrame -> SomeFrame
-- keepMptcpPackets frame = do
--     let mptcpStreams = getTcpStreams frame

-- TODO return MptcpStreamId instead
getMpTcpStreams :: SomeFrame -> [StreamIdMptcp]
getMpTcpStreams ps =
    catMaybes $
    L.fold L.nub $ (view mptcpStream <$> ps)

filterMptcpConnection :: SomeFrame -> StreamId Mptcp -> SomeFrame
filterMptcpConnection frame streamId =
  streamPackets
  where
    streamPackets = filterFrame  (\x -> x ^. mptcpStream == Just streamId) frame




-- buildMptcpConnectionFromRow :: Packet -> TcpConnection
-- buildMptcpConnectionFromRow r =
  -- MptcpConnection {
    -- srcIp = r ^. ipSource
    -- , dstIp = r ^. ipDest
    -- , srcPort = r ^. tcpSrcPort
    -- , dstPort = r ^. tcpDestPort
    -- , priority = Nothing  -- for now
    -- , localId = 0
    -- , remoteId = 0
    -- , subflowInterface = Nothing
  -- }


cmdListReinjections :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
cmdListReinjections args = do
  state <- P.get
  let loadedPcap = view loadedFile state
  res <- case loadedPcap of
    Nothing -> do
      log ( "please load a pcap first" :: String)
      return CMD.Continue
    Just frame -> do
      -- log $ "Number of rows " ++ show (frameLength frame)
      -- P.embed $ putStrLn $ "Number of MPTCP connections " ++ show (length mptcpStreams)
      -- P.embed $ putStrLn $ show mptcpStreams
      return CMD.Continue
      -- where
      --   reinjections = filterFrame (
  return res

listSubflowsCmd :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
listSubflowsCmd _args = do
  log "not implemented yet"
  return CMD.Continue

{-
-}
listMpTcpConnectionsCmd :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
listMpTcpConnectionsCmd _args = do
    -- TODO this part should be extracted so that
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> do
        log ( "please load a pcap first" :: String)
        return CMD.Continue
      Just frame -> do
        -- log $ "Number of rows " ++ show (frameLength frame)
        P.embed $ putStrLn $ "Number of MPTCP connections " ++ show (length mptcpStreams)
        P.embed $ putStrLn $ show mptcpStreams
        P.embed $ putStrLn $ concat $ map showEitherCon mptcpConnections
        -- >>
        return CMD.Continue
        where
          mptcpConnections :: [Either String Connection]
          mptcpConnections = map (\x -> fmap ffCon ( buildMptcpConnectionFromStreamId frame x)) mptcpStreams

          showEitherCon :: Either String Connection -> String
          showEitherCon (Left msg) = msg ++ "\n"
          showEitherCon (Right mptcpCon) = showConnection mptcpCon ++ "\n"

          mptcpStreams = getMpTcpStreams frame

