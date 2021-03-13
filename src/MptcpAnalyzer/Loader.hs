module MptcpAnalyzer.Loader
where
import MptcpAnalyzer.Types
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Pcap

import Prelude hiding (log)
import Control.Monad.Trans (liftIO)
import System.Exit (ExitCode(..))
import Colog.Polysemy (Log, log)
import Polysemy (Sem, Members, Embed)
import Polysemy.State as P
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import Frames

-- TODO return an Either or Maybe ?
-- return an either instead
loadPcapIntoFrame :: Members [Cache, Log String, Embed IO ] m => TsharkParams -> FilePath -> Sem m (Either String SomeFrame)
loadPcapIntoFrame params path = do
    log $ "Start loading pcap " ++ path
    x <- getCache cacheId
    case x of
      Right frame -> do
          log $ show cacheId ++ " in cache"
          return $ Right frame
      Left err -> do
          log $ "getCache error: " ++ err
          log "Calling tshark"
          -- TODO need to create a temporary file
          -- mkstemps
          -- TODO use showCommandForUser to display the run command to the user
          -- , stdOut, stdErr)
          (tempPath , exitCode, stdErr) <- liftIO $ withTempFileEx opts "/tmp" "mptcp.csv" (exportToCsv params path)
          if exitCode == ExitSuccess
              then do
                log $ "exported to file " ++ tempPath
                frame <- liftIO $ loadRows tempPath
                log $ "Number of rows after loading " ++ show (frameLength frame)
                cacheRes <- putCache cacheId frame
                -- use ifThenElse instead
                if cacheRes then
                  log "Saved into cache"
                else
                  pure ()
                return $ Right frame
              else do
                log $ "Error happened: " ++ show exitCode
                log stdErr
                log "error happened: exitCode"
                return $ Left stdErr

    where
      cacheId = CacheId [path] "" ""
      opts :: TempFileOptions
      opts = TempFileOptions True


-- buildTcpFrameFromFrame

-- \
buildAFrameFromStreamIdTcp :: Members [Cache, Log String, Embed IO ] m
    => TsharkParams
    -> FilePath
    -> StreamId Tcp
    -> Sem m (Either String (FrameFiltered Packet))
buildAFrameFromStreamIdTcp params pcapFilename streamId = do
    res <- loadPcapIntoFrame params pcapFilename
    return $ case res of
      Left err -> Left err
      Right frame -> buildConnectionFromTcpStreamId frame streamId

buildAFrameFromStreamIdMptcp :: Members [Cache, Log String, Embed IO ] m
    => TsharkParams
    -> FilePath
    -> StreamId Mptcp
    -> Sem m (Either String (FrameFiltered Packet))
buildAFrameFromStreamIdMptcp params pcapFilename streamId = do
  log $ "Building frame for mptcp stream " ++ show streamId
  res <- loadPcapIntoFrame params pcapFilename
  return $ case res of
    Left err -> Left err
    Right frame -> buildMptcpConnectionFromStreamId frame streamId
