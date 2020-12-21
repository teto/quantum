{-# LANGUAGE DataKinds, FlexibleContexts, QuasiQuotes, TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
module MptcpAnalyzer.Commands.Load
where
import Frames
-- import Frames.CSV
import Pcap
import MptcpAnalyzer.Commands.Utils as CMD
import Options.Applicative
import Control.Monad.Trans (liftIO)
-- import Control.Lens hiding (argument)

import MptcpAnalyzer.Cache
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Exit (ExitCode(..))
import Utils
import Prelude hiding (log)
import Colog.Polysemy (Log, log)
-- import Mptcp.Logging (Log, log)
-- import System.Environment (withProgName)
import Polysemy (Sem, Members, Embed)
import Polysemy.State as P


newtype ArgsLoadPcap = ArgsLoadPcap {
  pcap :: FilePath
}

loadPcapParser :: Parser ArgsLoadPcap
loadPcapParser = 
    ArgsLoadPcap
      -- TODO complete with filepath
      <$> argument str (metavar "PCAP" <> completeWith ["toto", "tata"]
          <> help "Target for the greeting"
      )

-- loadPcapParser :: ArgsLoadPcap
-- loadPcapParser = ArgsLoadPcap
--       -- TODO complete with filepath
--       <$> argument str (metavar "PCAP" <> completeWith ["toto", "tata"]
--           <> help "Target for the greeting"
--       )

-- TODO factor out
loadOpts :: ParserInfo ArgsLoadPcap
loadOpts = info (loadPcapParser <**> helper)
  ( fullDesc
  <> progDesc "Tool to provide insight in MPTCP (Multipath Transmission Control Protocol)\
              \performance via the generation of stats & plots"
  <> header "hello - a test for optparse-applicative"
  <> footer "You can report issues/contribute at https://github.com/teto/mptcpanalyzer"
  )


-- myHandleParseResult :: ParserResult a -> m CMD.RetCode
-- myHandleParseResult (Success a) = 

-- TODO move commands to their own module
-- TODO it should update the loadedFile in State !
-- handleParseResult
-- loadPcap :: CMD.CommandCb
-- loadPcap :: Members [Log, P.State MyState, Cache, Embed IO] m => [String] -> Sem m RetCode
loadPcap :: Members [Log String, P.State MyState, Cache, Embed IO] m => ArgsLoadPcap -> Sem m RetCode
loadPcap parsedArgs = do
    log "Called loadPcap"
    -- s <- gets
    -- liftIO $ withProgName "load" (
    -- TODO fix the name of the program, by "load"
    mFrame <- loadPcapIntoFrame defaultTsharkPrefs (pcap parsedArgs)
    -- fmap onSuccess mFrame
    case mFrame of
      Nothing -> return CMD.Continue
      Just _frame -> do
        -- prompt .= pcap parsedArgs ++ "> "
        modify (\s -> s { _prompt = pcap parsedArgs ++ "> ",
              _loadedFile = mFrame
            })
        log "Frame loaded" >> return CMD.Continue

-- TODO return an Either or Maybe ?
-- MonadIO m, KatipContext m
  -- EmbedIO
loadPcapIntoFrame :: Members [Cache, Log String, Embed IO ] m => TsharkParams -> FilePath -> Sem m (Maybe PcapFrame)
loadPcapIntoFrame params path = do
    log ("Start loading pcap " ++ path)
    x <- getCache cacheId
    case x of
      Right frame -> do
          log "Frame in cache"
          return $ Just frame
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
                cacheRes <- putCache cacheId tempPath
                -- use ifThenElse instead
                if cacheRes then
                  log "Saved into cache"
                else
                  pure ()

                return $ Just frame
              else do
                log $ "Error happened: " ++ show exitCode
                log stdErr
                log "error happened: exitCode"
                return Nothing

    where
      cacheId = CacheId [path] "" ""
      opts :: TempFileOptions
      opts = TempFileOptions True

-- loadCsv :: Members [Log, Cache, P.State MyState, Embed IO] m => [String] -> Sem m RetCode
loadCsv :: Members '[Log String, Cache, Embed IO] m => ArgsLoadPcap -> Sem m CMD.RetCode
loadCsv parsedArgs = do

    log $ "Loading " ++ csvFilename
    -- parsedArgs <- liftIO $ myHandleParseResult parserResult
    frame <- liftIO $ loadRows csvFilename
    -- TODO restore
    -- loadedFile .= Just frame
    log $ "Number of rows " ++ show (frameLength frame)
    log "Frame loaded" >> return CMD.Continue
    where
      csvFilename = pcap parsedArgs

