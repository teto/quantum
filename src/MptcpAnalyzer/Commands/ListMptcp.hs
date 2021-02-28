{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PackageImports #-}
module MptcpAnalyzer.Commands.ListMptcp
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
-- import MptcpAnalyzer.Commands.Utils as CMD
import MptcpAnalyzer.Commands.List as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types

import Net.Mptcp.Types (MptcpConnection(..), MptcpSubflow, showMptcpConnection)

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


-- keepMptcpPackets :: SomeFrame -> SomeFrame
-- keepMptcpPackets frame = do
--     let mptcpStreams = getTcpStreams frame

-- TODO return MptcpStreamId instead
getMpTcpStreams :: SomeFrame -> [StreamIdMptcp]
getMpTcpStreams ps =
    catMaybes $
    L.fold L.nub $ (view mptcpStream <$> ps)

filterMptcpConnection :: SomeFrame -> StreamId Mptcp -> SomeFrameF MptcpConnection
filterMptcpConnection frame streamId =
  streamPackets
  where
    streamPackets = filterFrame  (\x -> x ^. mptcpStream == Just streamId) frame

buildMptcpConnectionFromStreamId :: SomeFrame -> StreamId Mptcp -> Either String MptcpConnection
buildMptcpConnectionFromStreamId frame streamId = do
    -- Right $ frameLength synPackets
    if frameLength streamPackets < 1 then
      Left $ "No packet with mptcp.stream == " ++ show streamId
    else if frameLength synAckPackets < 1 then
      Left $ "No syn/ack packet found for stream" ++ show streamId ++ " First packet: "
      -- ++ show streamPackets
    else
      -- TODO now add a check on abstime
      -- if ds.loc[server_id, "abstime"] < ds.loc[client_id, "abstime"]:
      --     log.error("Clocks are not synchronized correctly")
      Right $ MptcpConnection {
        mptcpServerKey = fromJust $ synAckPacket ^. mptcpSendKey
        , mptcpClientKey = fromJust $ synPacket ^. mptcpSendKey
        , mptcpServerToken = fromJust $ synAckPacket ^. mptcpExpectedToken
        , mptcpClientToken = fromJust $ synPacket ^. mptcpExpectedToken
        , mptcpNegotiatedVersion = fromIntegral $ fromJust clientMptcpVersion :: Word8

        , subflows = Set.fromList subflows
        , localIds = Set.empty
        , remoteIds = Set.empty
      }
      --  $ frameRow synPackets 0
    where
      streamPackets :: SomeFrameF Mptcp
      streamPackets = filterFrame  (\x -> x ^. mptcpStream == Just streamId) frame
      -- suppose tcpflags is a list of flags, check if it is in the list
      -- of type FrameRec [(Symbol, *)]
      -- Looking for synack packets
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
      synAckPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags) && TcpFlagAck `elem` (x ^. tcpFlags)) streamPackets

      synPacket = frameRow synPackets 0
      synAckPacket = frameRow synAckPackets 0

      masterTcpstreamId = synPacket ^. tcpStream
      -- buildConnectionFromTcpStreamId frame masterTcpstreamId

      clientMptcpVersion = synPacket ^. mptcpVersion

      subflows = map (buildSubflow frame) (getTcpStreams streamPackets)


buildSubflow :: SomeFrame -> StreamId Tcp -> MptcpSubflow
buildSubflow frame (StreamId sfId) = case buildConnectionFromTcpStreamId frame (StreamId sfId) of
  Left _ -> error "should not happen"
  Right con -> con

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
          mptcpConnections :: [Either String MptcpConnection]
          mptcpConnections = map (buildMptcpConnectionFromStreamId frame) mptcpStreams

          showEitherCon :: Either String MptcpConnection -> String
          showEitherCon (Left msg) = msg ++ "\n"
          showEitherCon (Right mptcpCon) = showMptcpConnection mptcpCon ++ "\n"

          mptcpStreams = getMpTcpStreams frame

