module MptcpAnalyzer.Commands.Reinjections
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
import Polysemy.Trace as P
import Colog.Polysemy (Log, log)
import Data.Function (on)
import Data.List (sortBy, sortOn)
import Data.Either (rights, lefts)
import Frames
import Frames.CSV
import Frames.Rec
import Data.Maybe
import Control.Lens ((^.))
import Data.Foldable (toList)
import qualified Data.Foldable as F
import qualified Pipes as P
import qualified Pipes.Prelude as P
import Data.List (intercalate)
import Control.Lens hiding (argument)

piListReinjections :: ParserInfo CommandArgs
piListReinjections = info (
    (parserListReinjections )
    <**> helper)
  ( progDesc "List MPTCP reinjections"
  )
  where
    -- parserListReinjections :: Parser CommandArgs
    parserListReinjections =
          ArgsListReinjections <$>
          -- strArgument (
          --     metavar "PCAP1"
          --     <> help "File to analyze"
          -- )
          -- <*>
          argument readStreamId (
              metavar "TCP_STREAM"
              <> help "stream id to analyze"
          )

piQualifyReinjections :: ParserInfo CommandArgs
piQualifyReinjections = info (
    (parserQualifyReinjections ) <**> helper)
  ( progDesc "Qualifies MPTCP reinjections"
  )


parserQualifyReinjections :: Parser CommandArgs
parserQualifyReinjections =
      ArgsQualifyReinjections <$>
      strArgument (
          metavar "PCAP1"
          <> help "File to analyze"
      )
      <*> argument readStreamId (
          metavar "TCP_STREAM"
          <> help "stream id to analyze"
      )
      <*> strArgument (
          metavar "PCAP2"
          <> help "File to analyze"
      )
      <*> argument readStreamId (
          metavar "TCP_STREAM"
          <> help "stream id to analyze"
      )
      <*> switch (
          long "verbose"
          <> help "Verbose or not"
      )

cmdListReinjections :: Members '[Log String, P.State MyState, Cache, Embed IO] r
    => StreamId Mptcp
    -> Sem r RetCode
cmdListReinjections streamId = do
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

-- Analyzes row of reinject packets
-- Compares arrival time of the first send of a segment with the
-- analyzeReinjection :: (FrameRec SenderReceiverCols) -> Record SenderReceiverCols -> Double
analyzeReinjection mergedFrame row = 
  let
    -- a list of packetIds
    reinjectOf = fromJust (rgetField @SndReinjectionOf row)
    initialPktId = head reinjectOf

    -- it is a frame

    originalPkt :: Record SenderReceiverCols
    originalPkt = let 
          originalFrame = filterFrame (\x -> x ^. sndPacketId == initialPktId) mergedFrame
      in case frameLength (originalFrame) of
      0 -> error "empty frame"
      _ -> frameRow originalFrame 0

    origArrival, reinjArrival :: Double
    origArrival = rgetField @RcvRelTime originalPkt
    reinjArrival = rgetField @RcvRelTime originalPkt
    reinjPktId = row ^. sndPacketId

    delta = reinjArrival - origArrival
  in
    delta

cmdQualifyReinjections :: Members '[Log String, P.State MyState, Cache, P.Trace, Embed IO] r
  => CommandArgs -> Sem r RetCode
cmdQualifyReinjections (ArgsQualifyReinjections pcap1 streamId1 pcap2 streamId2 verbose ) = do
  eframe1 <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap1 streamId1
  eframe2 <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap2 streamId2
  res <- case (eframe1, eframe2 ) of
    (Right aframe1, Right aframe2) ->
        -- TODO need to convert to senderReceiver
        let
          mergedRes = mergeMptcpConnectionsFromKnownStreams aframe1 aframe2
          mbRecs = map recMaybe mergedRes
          justRecs = catMaybes mbRecs
          -- myFrame ::
          myFrame = convertToSenderReceiver mergedRes

          reinjectedPacketsFrame = filterFrame (\x -> isJust $ x ^. sndReinjectionOf) myFrame

          -- loop over these reinjectpackets
          -- assume both were mapped
          reinjects = fmap (analyzeReinjection myFrame) reinjectedPacketsFrame

          showReinjects frame =
            -- unlines (intercalate sep (columnHeaders (Proxy :: Proxy (Record rs))) : rows)
            intercalate "," rows
            where
              rows = P.toList (F.mapM_ (P.yield . show ) frame)

        in do
          trace $ "Result of the analysis; reinjections:" ++ showReinjects reinjects
          trace $ "Merged mptcp connection" ++ showFrame "," reinjectedPacketsFrame

          -- qualifyReinjections tempPath handle (getDests dest) (ffCon aframe1) mergedRes
          return CMD.Continue
    (Left err, _) -> return $ CMD.Error err
    (_, Left err) -> return $ CMD.Error err


  return CMD.Continue
  where
    -- mergedPcap
    -- reinjectedPackets = filterFrame (sndReinjectionOf) (toFrame justRecs)
cmdQualifyReinjections _ = error "unsupported"

-- qualifyReinjections :: Members '[Log String, P.State MyState, Cache, Embed IO] r 
--     => MergedPcap
--     -> Sem r RetCode
-- qualifyReinjections mergedRes (getDests dest)
