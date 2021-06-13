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
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Data.Function (on)
import Data.List (sortBy, sortOn, intersperse, intercalate)
import Data.Either (rights, lefts)
import Frames
import Frames.CSV
import Frames.Rec
import Data.Maybe
import Control.Lens ((^.))
import Data.Foldable (toList)
import qualified Data.Foldable as F
import qualified Pipes as Pipes
import qualified Pipes.Prelude as Pipes
import Control.Lens hiding (argument)

import qualified Debug.Trace as D

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
    (parserQualifyReinjections) <**> helper)
  ( progDesc "Qualifies MPTCP reinjections"
  <> footer "analyze examples/client_2_redundant.pcapng 0 examples/server_2_redundant.pcapng 0"
  )


parserQualifyReinjections :: Parser CommandArgs
parserQualifyReinjections =
      ArgsQualifyReinjections
      <$> parserPcapMapping False
      <*> switch (
          long "verbose"
          <> help "Verbose or not"
      )

cmdListReinjections :: (Members '[Log, P.Trace, P.State MyState, Cache, Embed IO] r)
    => StreamId Mptcp
    -> Sem r RetCode
cmdListReinjections streamId = do
  state <- P.get
  let loadedPcap = view loadedFile state
  case loadedPcap of
    Nothing -> do
      trace "please load a pcap first"
      return CMD.Continue
    Just (frame :: FrameRec HostCols) -> do
      let
        reinjectedPacketsFrame = filterFrame (\x -> isJust $ x ^. reinjectionOf) frame
      -- log $ "Number of rows " ++ show (frameLength frame)
        outputs = fmap showReinjections reinjectedPacketsFrame
      -- P.embed $ putStrLn $ "Number of MPTCP connections " ++ show (length mptcpStreams)
      -- P.embed $ putStrLn $ show mptcpStreams
      P.trace $ intercalate "\n" (toList outputs)
      return CMD.Continue
      where
        -- packetid=757 (tcp.stream 1) is a reinjection of 1 packet(s):
        -- - packet 256 (tcp.stream 7)
        showReinjections row = "packetid=" ++ show (row ^. packetId) ++ " (tcp.stream " ++ show (row ^. tcpStream) ++ ")\n"
            -- TODO map over the list
            ++ intercalate "\n" ( map showReinjection (fromJust $ row ^. reinjectionOf))

        showReinjection reinjection = case toList $ filterFrame (\x -> x ^. packetId == reinjection) (frame) of
          [] -> error "did not find original packet"
          rows -> "- Reinjection of " ++ show reinjection ++ "(tcp.stream " ++ show ( (head rows)  ^. tcpStream) ++ ")"

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

cmdQualifyReinjections ::
  Members '[
    Log
    , P.State MyState
    , Cache
    , P.Trace
    , Embed IO
    ] r
  => PcapMapping Mptcp
  -> Bool -> Sem r RetCode
cmdQualifyReinjections (PcapMapping pcap1 streamId1 pcap2 streamId2) verbose = do
  eframe1 <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap1 streamId1
  eframe2 <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap2 streamId2
  res <- case (eframe1, eframe2 ) of
    (Right aframe1, Right aframe2) -> do
          mergedRes <- mergeMptcpConnectionsFromKnownStreams aframe1 aframe2
          let
            -- mergedRes = mergeMptcpConnectionsFromKnownStreams' aframe1 aframe2

            mbRecs = map recMaybe mergedRes
            -- packets that could be mapped in both pcaps
            justRecs = catMaybes mbRecs
            myFrame = convertToSenderReceiver mergedRes

            reinjectedPacketsFrame = filterFrame (\x -> isJust $ x ^. sndReinjectionOf) myFrame

            -- loop over these reinjectpackets
            -- assume both were mapped
            reinjects = fmap (analyzeReinjection myFrame) reinjectedPacketsFrame

            showReinjects frame =
              -- unlines (intercalate sep (columnHeaders (Proxy :: Proxy (Record rs))) : rows)
              intercalate "," rows
              where
                rows = Pipes.toList (F.mapM_ (Pipes.yield . show ) frame)
          -- Log.info $ "Result of the analysis; reinjections:"
            -- <> tshow (showReinjects justRecs)
          P.embed $ writeMergedPcap ("mergedRes-"  ++ ".csv") mergedRes
          P.embed $ writeDSV defaultParserOptions ("sndrcv-merged-"  ++ ".csv") myFrame
          trace $ "Size after conversion to sender/receiver " ++ show (frameLength myFrame)
          trace $ "Number of reinjected packets: " ++ show (frameLength reinjectedPacketsFrame)

          trace $ "Result of the analysis; reinjections:" ++ showReinjects reinjects
          -- trace $ "Merged mptcp connection\nFrame size: " ++ show (frameLength reinjectedPacketsFrame)
                  -- ++ "\n" ++ showFrame "," reinjectedPacketsFrame

          -- qualifyReinjections tempPath handle (getDests dest) (ffCon aframe1) mergedRes
          return CMD.Continue
    (Left err, _) -> return $ CMD.Error err
    (_, Left err) -> return $ CMD.Error err


  return CMD.Continue
  where
    -- mergedPcap
    -- reinjectedPackets = filterFrame (sndReinjectionOf) (toFrame justRecs)

-- qualifyReinjections :: Members '[Log String, P.State MyState, Cache, Embed IO] r 
--     => MergedPcap
--     -> Sem r RetCode
-- qualifyReinjections mergedRes (getDests dest)
