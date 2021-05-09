{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PackageImports #-}
module MptcpAnalyzer.Commands.ListMptcp
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.List as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Stream
import Net.Mptcp

-- import Net.Mptcp.Types (MptcpConnection(..), MptcpSubflow, showMptcpConnection)

import "mptcp-pm" Net.Tcp (TcpFlag(..))
import Prelude hiding (log)
import Options.Applicative
import Frames
import Control.Lens hiding (argument)
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Polysemy.Trace as P
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



cmdListSubflows :: Members '[Log String, P.State MyState, P.Trace, Cache, Embed IO] r
  => Bool -- ^ Detailed
  -> Sem r RetCode
cmdListSubflows detailed = do
  P.trace "not implemented yet"
  return CMD.Continue

{-
-}
cmdListMptcpConnections ::
  Members [Log String, P.Trace, P.State MyState, Cache, P.Embed IO] r
  => Bool -- ^ Detailed
  -> Sem r RetCode
cmdListMptcpConnections _detailed = do
    -- TODO this part should be extracted so that
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> do
        log ( "please load a pcap first" :: String)
        return CMD.Continue
      Just frame -> do
        -- log $ "Number of rows " ++ show (frameLength frame)
        P.trace $ "Number of MPTCP connections " ++ show (length mptcpStreams)
        P.trace $ show mptcpStreams
        P.trace $ concat $ map showEitherCon mptcpConnections
        -- >>
        return CMD.Continue
        where
          mptcpConnections :: [Either String MptcpConnection]
          mptcpConnections = map (\x -> fmap ffCon ( buildMptcpConnectionFromStreamId frame x)) mptcpStreams

          showEitherCon :: Either String MptcpConnection -> String
          showEitherCon (Left msg) = msg ++ "\n"
          showEitherCon (Right mptcpCon) = showConnection mptcpCon ++ "\n"

          mptcpStreams = getMpTcpStreams frame

