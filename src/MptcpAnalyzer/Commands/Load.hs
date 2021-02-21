{-# LANGUAGE DataKinds, FlexibleContexts, QuasiQuotes, TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
module MptcpAnalyzer.Commands.Load
where
import Frames
-- import Frames.CSV
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Commands.Utils as CMD
import MptcpAnalyzer.Commands.Definitions as CMD
import Options.Applicative
import Control.Monad.Trans (liftIO)
-- import Control.Lens hiding (argument)

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Definitions
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Exit (ExitCode(..))
import Prelude hiding (log)
import Colog.Polysemy (Log, log)
import Polysemy (Sem, Members, Embed)
import Polysemy.State as P

loadPcapArgs :: Parser CommandArgs
loadPcapArgs =  ArgsLoadPcap <$> argument str (metavar "PCAP" <> completeWith ["toto", "tata"]
          <> help "Load a Pcap file"
      )

loadCsvArgs :: Parser CommandArgs
loadCsvArgs =  ArgsLoadCsv <$> argument str (metavar "PCAP" <> completeWith ["toto", "tata"]
          <> help "Load a Csv file"
      )

loadCsvOpts :: ParserInfo CommandArgs
loadCsvOpts = info (loadCsvArgs <**> helper)
  ( fullDesc
  <> progDesc "Load a csv file generated from wireshark"
  )

loadPcapOpts :: ParserInfo CommandArgs
loadPcapOpts = info (loadPcapArgs <**> helper)
  ( fullDesc
  <> progDesc "Load a pcap file via wireshark"
  )


-- myHandleParseResult :: ParserResult a -> m CMD.RetCode
-- myHandleParseResult (Success a) = 

-- TODO move commands to their own module
-- TODO it should update the loadedFile in State !
-- handleParseResult
-- loadPcap :: CMD.CommandCb
-- loadPcap :: Members [Log, P.State MyState, Cache, Embed IO] m => [String] -> Sem m RetCode
loadPcap :: Members [Log String, P.State MyState, Cache, Embed IO] m => CommandArgs -> Sem m RetCode
loadPcap args = do
    log $ "loading pcap " ++ pcapFilename
    -- s <- gets
    -- liftIO $ withProgName "load" (
    -- TODO fix the name of the program, by "load"
    mFrame <- loadPcapIntoFrame defaultTsharkPrefs pcapFilename
    -- fmap onSuccess mFrame
    case mFrame of
      Nothing -> return CMD.Continue
      Just _frame -> do
        -- prompt .= pcap parsedArgs ++ "> "
        modify (\s -> s { _prompt = pcapFilename ++ "> ",
              _loadedFile = mFrame
            })
        log "Frame loaded" >> return CMD.Continue
    where
      pcapFilename = loadPcapPath args

-- TODO return an Either or Maybe ?
loadPcapIntoFrame :: Members [Cache, Log String, Embed IO ] m => TsharkParams -> FilePath -> Sem m (Maybe PcapFrame)
loadPcapIntoFrame params path = do
    log $ "Start loading pcap " ++ path
    x <- getCache cacheId
    case x of
      Right frame -> do
          log $ show cacheId ++ " in cache"
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
                cacheRes <- putCache cacheId frame
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


loadCsv :: Members '[Log String, State MyState, Cache, Embed IO] m => CommandArgs -> Sem m CMD.RetCode
loadCsv (ArgsLoadCsv csvFilename)  = do

    log $ "Loading " ++ csvFilename
    -- parsedArgs <- liftIO $ myHandleParseResult parserResult
    frame <- liftIO $ loadRows csvFilename
    -- TODO restore
    -- loadedFile .= Just frame
    modify (\s -> s { _loadedFile = Just frame })
    log $ "Number of rows " ++ show (frameLength frame)
    log "Frame loaded" >> return CMD.Continue
    -- where
    --   csvFilename = loadCsvPath parsedArgs

loadCsv _ = error "unsupported "
