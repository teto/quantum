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
import Data.List (sortBy)

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
cmdMapTcpConnection :: Members '[Log String, P.State MyState, Cache, Embed IO] r => CommandArgs -> Sem r RetCode
cmdMapTcpConnection (ArgsMapTcpConnections pcap1 pcap2 streamId) = do
  log $ "Mapping tcp connections"
  res <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap1 streamId
  res2 <- loadPcapIntoFrame defaultTsharkPrefs pcap2
  case (res, res2) of
    (Right aframe, Right frame) -> do
      -- TODO sort results and print them
      let scores = map (evalScore (ffCon aframe) frame) (getTcpStreams frame)
      _ <- mapM displayScore (sortBy (compare `on` snd) scores)
      return CMD.Continue
    _ -> return $ CMD.Error "An error happened"

  where
    evalScore con1 frame streamId' = case buildConnectionFromTcpStreamId frame streamId' of
      Left err -> (con1, 0)
      Right (FrameTcp con2 _) -> (con2, scoreTcpCon con1 con2)

    displayScore (con, score) = log $ "Score for connection " ++ showConnection con ++ ":\n" ++ show score

cmdMapTcpConnection _ = error "undefined "
    -- streamId = argsMapTcpStream args
-- mapTcpConnection :: Connection -> Connection
