{-# LANGUAGE DataKinds, FlexibleContexts, QuasiQuotes, TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
module MptcpAnalyzer.Commands.Load
where
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Types
-- import Control.Lens hiding (argument)

import Frames
import Options.Applicative
import Control.Monad.Trans (liftIO)
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
      Left _ -> return CMD.Continue
      Right frame -> do
        -- prompt .= pcap parsedArgs ++ "> "
        modify (\s -> s { _prompt = pcapFilename ++ "> ",
              _loadedFile = Just frame
            })
        log "Frame loaded" >> return CMD.Continue
    where
      pcapFilename = loadPcapPath args


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
