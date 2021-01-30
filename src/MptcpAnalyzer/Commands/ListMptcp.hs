{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PackageImports #-}
module MptcpAnalyzer.Commands.ListMptcp
where

import Prelude hiding (log)
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.Utils as CMD
import MptcpAnalyzer.Definitions
import Net.Tcp (TcpConnection(..), TcpFlag(..), showTcpConnection)
import Net.Mptcp.Types (MptcpConnection(..))
import Options.Applicative
import MptcpAnalyzer.Pcap
import Frames
import Control.Lens hiding (argument)
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)
import Data.Word (Word16, Word32, Word64)
import qualified Control.Foldl as L
import qualified Data.Set as Set
import qualified Pipes.Prelude as PP
import Data.Maybe (catMaybes)

listMpTcpOpts :: Member Command r => ParserInfo (Sem r CMD.RetCode)
listMpTcpOpts = info (
   CMD.listMpTcpConnections <$> parserList <**> helper)
  ( progDesc "List MPTCP connections"
  )
  where
    parserList = ParserListSubflows <$> switch ( long "detailed" <> help "detail connections")

-- keepMptcpPackets :: PcapFrame -> PcapFrame
-- keepMptcpPackets frame = do
--     let mptcpStreams = getTcpStreams frame

-- TODO return MptcpStreamId instead
getMpTcpStreams :: PcapFrame -> [Word32]
getMpTcpStreams ps =
    catMaybes $
    L.fold L.nub $ (view mptcpStream <$> ps)

buildMptcpConnectionFromStreamId :: PcapFrame -> StreamId Mptcp -> Either String MptcpConnection
buildMptcpConnectionFromStreamId frame (StreamId streamId) = do
    -- Right $ frameLength synPackets
    if frameLength streamPackets < 1 then
      Left $ "No packet with mptcp.stream == " ++ show streamId
    else if frameLength synAckPackets < 1 then
      Left $ "No syn/ack packet found for stream" ++ show streamId
    else 
      Right $ buildCon
      --  $ frameRow synPackets 0
    where
      streamPackets = filterFrame  (\x -> x ^. mptcpStream == Just streamId) frame
      -- suppose tcpflags is a list of flags, check if it is in the list
      -- of type FrameRec [(Symbol, *)]
      -- Looking for synack packets
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
      synAckPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags) && TcpFlagAck `elem` (x ^. tcpFlags)) streamPackets

      synPacket = frameRow synPackets 0
      synAckPacket = frameRow synAckPackets 0

      clientMptcpVersion = synPacket ^. mptcpVersion

      buildCon = MptcpConnection {
        mptcpServerKey = 0
        , mptcpClientKey = 0
        , mptcpServerToken = 0
        , mptcpClientToken = 0
        , mptcpNegotiatedVersion = 0

        , subflows = Set.empty
        , localIds = Set.empty
        , remoteIds = Set.empty
      }

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
        let tcpStreams = getMpTcpStreams frame
        -- log $ "Number of rows " ++ show (frameLength frame)
        P.embed $ putStrLn $ "Number of MPTCP connections " ++ show (length tcpStreams)
        P.embed $ putStrLn $ show tcpStreams
        -- mapM (putStrLn . showTcpConnection <$> buildConnectionFromTcpStreamId frame ) tcpStreams
        -- >>
        return CMD.Continue
