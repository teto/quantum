module MptcpAnalyzer.Commands.Map
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
-- import MptcpAnalyzer.Commands.Utils as CMD
import MptcpAnalyzer.Commands.List as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Merge

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
    parserMapTcp <**> helper)
  ( progDesc "Attempts to map a TCP connection to another one"
  )

parserMapTcp :: Parser CommandArgs
parserMapTcp =
      ArgsMapTcpConnections <$>
      strArgument (
          metavar "PCAP1"
          <> help "File to analyze"
      )
      <*> strArgument (
          metavar "PCAP2"
          <> help "File to analyze"
      )
      <*> argument readStreamId (
          metavar "TCP_STREAM"
          <> help "stream id to analyzer"
      )

-- |
-- todo pass an exhaistove flag ?
cmdMapTcpConnection :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
cmdMapTcpConnection (ArgsMapTcpConnections pcap1 pcap2 streamId) = do
  log $ "Mapping tcp connections"
  res <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap1 streamId
  res2 <- loadPcapIntoFrame defaultTsharkPrefs pcap2
  case (res, res2) of
    (Right aframe, Right frame) -> do
      let streamsToCompare = (getTcpStreams frame)
      let consToCompare = map (buildConnectionFromTcpStreamId frame) (getTcpStreams frame)
      log $ "Best match for " ++ show (ffCon aframe) ++ " is "
      log $ "Comparing with stream " ++ show streamsToCompare
      -- TODO sort results and print them
      let scores = map (evalScore (ffCon aframe)) (rights consToCompare)
      -- let sortedScores = (sortBy (compare `on` snd) scores)
      let sortedScores = (sortOn snd scores)
      -- TODO only display X first take 5
      mapM_ displayScore sortedScores
      -- display failures
      mapM_ displayFailure (lefts consToCompare)
      return CMD.Continue
    _ -> return $ CMD.Error "An error happened"
      -- Left err -> error $ "error happened for tcp.stream " ++ show streamId'


  where
    -- evalScore con1 frame streamId' = case buildConnectionFromTcpStreamId frame streamId' of
    evalScore con1 (FrameTcp con2 _) = (con2, scoreTcpCon con1 con2)

    displayScore (con, score) = log $ "Score for connection " ++ showConnection con ++ ": " ++ show score
    displayFailure err = log $ "Couldn't compute score for streamId  " ++ show err

cmdMapTcpConnection _ = error "undefined "
    -- streamId = argsMapTcpStream args
-- mapTcpConnection :: Connection -> Connection
