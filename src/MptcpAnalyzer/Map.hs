{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PackageImports #-}
module MptcpAnalyzer.Map
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.List as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Merge
import MptcpAnalyzer.Stream
import Net.Tcp
import Net.Mptcp

import Prelude hiding (log)
import Options.Applicative
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)
import Data.Function (on)
import Data.List (sortBy, sortOn)
import Data.Either (rights, lefts)


-- |
-- Returns a list of 
mapTcpConnection ::
  -- Members '[Log String, P.State MyState, Cache, Embed IO] r => 
  FrameFiltered TcpConnection Packet
  -> Frame Packet
  -> [(TcpConnection, Int)]
  -- ^ (connection, score)
mapTcpConnection aframe frame = let
      streamsToCompare = getTcpStreams frame
      consToCompare = map (buildTcpConnectionFromStreamId frame) (getTcpStreams frame)
      scores = map (evalScore (ffCon aframe)) (rights consToCompare)
      sortedScores = sortOn snd scores
      evalScore con1 (FrameTcp con2 _) = (con2, similarityScore con1 con2)
    in
      sortedScores


-- | Returns
mapSubflows :: MptcpConnection -> MptcpConnection -> [MptcpSubflow, (MptcpSubflow, Int)]
mapSubflows con1 con2 =
  map selectBest (mpconSubflows con1)
  [ (sf1, scoreSubflows sf1) | sf1 <- (mpconSubflows con1) ]
  where
    -- select best / sortOn
    scoreSubflows sf1 = map (\sf -> (sf, similarityScore sf1 sf)) (mpconSubflows cons2)

-- |
-- map_mptcp_connection_from_known_streams
mapMptcpConnection ::
  FrameFiltered TcpConnection Packet
  -> Frame Packet
  -> [(MptcpConnection, Int)]
  -- ^ (connection, score)
mapMptcpConnection aframe frame = let
      streamsToCompare = getMptcpStreams frame
      consToCompare = map (buildTcpConnectionFromStreamId frame) (getTcpStreams frame)
      scores = map (evalScore (ffCon aframe)) (rights consToCompare)
      sortedScores = sortOn snd scores
      evalScore con1 (FrameTcp con2 _) = (con2, similarityScore con1 con2)
    in

-- map_tcp_connection examples/client_1_tcp_only.pcap examples/server_1_tcp_only.pcap  0
-- do_map_tcp_connection(self, args):
