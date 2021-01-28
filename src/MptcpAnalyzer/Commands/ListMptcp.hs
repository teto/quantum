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

getMpTcpStreams :: PcapFrame -> [Maybe Word32]
getMpTcpStreams ps =
    L.fold L.nub (view mptcpStream <$> ps)

buildMptcpConnectionFromStreamId :: PcapFrame -> Either String MptcpConnection
buildMptcpConnectionFromStreamId frame = do
  return $ MptcpConnection {
    mptcpServerKey = 0
    , mptcpClientKey = 0
    , mptcpServerToken = 0
    , mptcpClientToken = 0

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
        -- mapM (putStrLn . showTcpConnection <$> buildConnectionFromTcpStreamId frame ) tcpStreams
        -- >>
        return CMD.Continue
