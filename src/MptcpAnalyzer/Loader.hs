module MptcpAnalyzer.Loader
where
import MptcpAnalyzer.Types
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Frame

import Prelude hiding (log)
import Control.Monad.Trans (liftIO)
import System.Exit (ExitCode(..))
-- import Colog.Polysemy (Log, log)
import Colog.Polysemy.Formatting
import Formatting
import Polysemy (Sem, Members, Embed)
import Polysemy.State as P
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import Frames
import Frames.CSV
import Net.Tcp
import Net.Mptcp
import qualified Frames.InCore




-- TODO return an Either or Maybe ?
-- return an either instead
loadPcapIntoFrame ::
    (Frames.InCore.RecVec a
    , Frames.CSV.ReadRec a
    , WithLog m
    , Members [Cache, Embed IO ] m)
    => TsharkParams
    -> FilePath
    -> Sem m (Either String (FrameRec a))
loadPcapIntoFrame params path = do
    logInfo ("Start loading pcap " % shown) path
    x <- getCache cacheId
    case x of
      Right frame -> do
          logDebug (shown % " in cache") cacheId
          return $ Right frame
      Left err -> do
          logDebug ("cache miss: " % shown) err
          logDebug "Calling tshark"
          (tempPath , exitCode, stdErr) <- liftIO $ withTempFileEx opts "/tmp" "mptcp.csv" (exportToCsv params path)
          if exitCode == ExitSuccess
              then do
                logDebug ("exported to file " % shown ) tempPath
                frame <- liftIO $ loadRows tempPath
                logDebug ( "Number of rows after loading " % hex) (frameLength frame)
                cacheRes <- putCache cacheId frame
                -- use ifThenElse instead
                if cacheRes then
                  logInfo "Saved into cache"
                else
                  pure ()
                return $ Right frame
              else do
                logInfo ("Error happened: " % shown) exitCode
                logInfo shown stdErr
                return $ Left stdErr

    where
      cacheId = CacheId [path] "" ""
      opts :: TempFileOptions
      opts = TempFileOptions True



-- loadMergedTcpStream :: 
--     FilePath -> StreamId Tcp
--     -> FilePath -> StreamId Tcp
--     -> MergedPcap
--         eframe1 <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap1 (StreamId streamId1)
--         -- TODO
--         eframe2 <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap2 (StreamId streamId2)

--         -- embed $ writeDSV defaultParserOptions "retyped.csv" processedFrame2
--         res <- case (eframe1, eframe2 ) of
--           (Right aframe1, Right aframe2) -> do
--               let mergedRes = mergeTcpConnectionsFromKnownStreams aframe1 aframe2
--               let mbRecs = map recMaybe mergedRes
--               let justRecs = catMaybes mbRecs
--               Plots.cmdPlotTcpOwd tempPath handle (getDests dest) (ffCon aframe1) mergedRes


-- buildTcpFrameFromFrame
-- \ Build a frame with only packets belonging to @streamId@
buildAFrameFromStreamIdTcp :: (WithLog m, Members [Cache, Embed IO ] m)
    => TsharkParams
    -> FilePath
    -> StreamId Tcp
    -> Sem m (Either String (FrameFiltered TcpConnection Packet))
buildAFrameFromStreamIdTcp params pcapFilename streamId = do
    res <- loadPcapIntoFrame params pcapFilename
    return $ case res of
      Left err -> Left err
      Right frame -> buildTcpConnectionFromStreamId frame streamId

buildAFrameFromStreamIdMptcp :: (WithLog m, Members [Cache, Embed IO ] m)
    => TsharkParams
    -> FilePath
    -> StreamId Mptcp
    -> Sem m (Either String (FrameFiltered MptcpConnection Packet))
buildAFrameFromStreamIdMptcp params pcapFilename streamId = do
  logDebug  ("Building frame for mptcp stream " % shown) streamId
  res <- loadPcapIntoFrame params pcapFilename
  return $ case res of
    Left err -> Left err
    Right frame -> buildMptcpConnectionFromStreamId frame streamId
