module MptcpAnalyzer.Commands.Map
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.List as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Merge
import MptcpAnalyzer.Stream

import Prelude hiding (log)
import Options.Applicative
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)
import Data.Function (on)
import Data.List (sortBy, sortOn)
import Data.Either (rights, lefts)

mapTcpOpts :: ParserInfo CommandArgs
mapTcpOpts = info (
    (parserMapConnection False) <**> helper)
  ( progDesc "Attempts to map a TCP connection to another one"
  )

mapMptcpOpts :: ParserInfo CommandArgs
mapMptcpOpts = info (
    (parserMapConnection True)<**> helper)
  ( progDesc "Maps a MPTCP connection to another one"
  )

parserMapConnection :: Bool -> Parser CommandArgs
parserMapConnection forMptcp =
      ArgsMapTcpConnections <$>
      strArgument (
          metavar "PCAP1"
          <> help "File to analyze"
      )
      <*> strArgument (
          metavar "PCAP2"
          <> help "File to analyze"
      )
      -- readStreamId
      <*> argument auto (
          metavar "TCP_STREAM"
          <> help "stream id to analyzer"
      )
      <*> switch (
          long "verbose"
          <> help "Verbose or not"
      )
      <*> option auto (
          metavar "LIMIT"
        <> Options.Applicative.value 10

          <> help "Limit the number of comparisons to display"
      )
      <*> option auto (
          metavar "MPTCP"
        -- internal is stronger than --belive, hides from all descriptions
        <> internal
        <> Options.Applicative.value forMptcp
        <> help ""
      )

-- |
-- todo this should be better handled
cmdMapTcpConnection :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
cmdMapTcpConnection args@ArgsMapTcpConnections{} = do
  if argsMapMptcp args then
    mapMptcpConnection args
  else
    mapTcpConnection args
cmdMapTcpConnection _ = undefined



-- TODO this could be made polymorphic using StreamConnection
mapTcpConnection :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
mapTcpConnection (ArgsMapTcpConnections pcap1 pcap2 streamId verbose limit _) = do
  log $ "Mapping tcp connections"
  res <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap1 (StreamId streamId)
  res2 <- loadPcapIntoFrame defaultTsharkPrefs pcap2
  case (res, res2) of
    (Right aframe, Right frame) -> do
      -- let streamsToCompare = (getTcpStreams frame)
      -- let consToCompare = map (buildTcpConnectionFromStreamId frame) (getTcpStreams frame)
      log $ "Best match for " ++ show (ffCon aframe) ++ " is "
      log $ "Comparing with stream " ++ show streamsToCompare
      -- TODO sort results and print them
      let sortedScores = mapTcpConnection aframe frame
      -- TODO only display X first take 5
      mapM_ displayScore sortedScores
      -- display failures
      mapM_ displayFailure (lefts consToCompare)
      return CMD.Continue
    _ -> return $ CMD.Error "An error happened"
  where

    displayScore (con, score) = log $ "Score for connection " ++ showConnection con ++ ": " ++ show score
    displayFailure err = log $ "Couldn't compute score for streamId  " ++ show err


mapMptcpConnection :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
mapMptcpConnection (ArgsMapTcpConnections pcap1 pcap2 streamId verbose limit True) = do
  log $ "Mapping mptcp connections"
  res <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap1 (StreamId streamId)
  res2 <- loadPcapIntoFrame defaultTsharkPrefs pcap2
  case (res, res2) of
    (Right aframe, Right frame) -> do
      let streamsToCompare = (getMptcpStreams frame)
      let consToCompare = map (buildTcpConnectionFromStreamId frame) (getTcpStreams frame)
      log $ "Best match for " ++ show (ffCon aframe) ++ " is "
      log $ "Comparing with stream " ++ show streamsToCompare
      let scores = map (evalScore (ffCon aframe)) (rights consToCompare)
      let sortedScores = (sortOn snd scores)
      mapM_ displayScore sortedScores
      mapM_ displayFailure (lefts consToCompare)
      return CMD.Continue
    _ -> return $ CMD.Error "An error happened"
  where
    evalScore con1 (FrameTcp con2 _) = (con2, similarityScore con1 con2)

    displayScore (con, score) = log $ "Score for connection " ++ showConnection con ++ ": " ++ show score
    displayFailure err = log $ "Couldn't compute score for streamId  " ++ show err

