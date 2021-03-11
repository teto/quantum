{-|
Description : Mptcpanalyzer
Maintainer  : matt
Stability   : testing
Portability : Linux

TemplateHaskell for Katip :(
-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE LambdaCase             #-}
{-# LANGUAGE TypeApplications             #-}
{-# LANGUAGE RankNTypes             #-}

module Main where

-- for monadmask
-- import Control.Monad.Catch
-- import qualified Data.Map         as HM
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Types
-- import qualified MptcpAnalyzer.Commands.Utils as CMD
import MptcpAnalyzer.Commands
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.List as CLI
import MptcpAnalyzer.Commands.ListMptcp as CLI
import MptcpAnalyzer.Commands.Export as CLI
import MptcpAnalyzer.Commands.Plot as Plots
import MptcpAnalyzer.Plots.Types
import qualified MptcpAnalyzer.Commands.Load as CL
-- import Control.Monad (void)

import Polysemy (Sem, Members, runFinal, Final)
import qualified Polysemy as P
-- import Polysemy.Reader as P
import qualified Polysemy.IO as P
import qualified Polysemy.State as P
import qualified Polysemy.Embed as P
import qualified Polysemy.Internal as P
-- import qualified Polysemy.Output as P
-- import qualified Polysemy.Trace as P
import System.FilePath
import System.Directory
import Prelude hiding (concat, init, log)
import Options.Applicative
import Colog.Core.IO (logStringStdout)
import Colog.Polysemy (Log, log, runLogAction)
import Graphics.Rendering.Chart.Easy hiding (argument)
import Graphics.Rendering.Chart.Backend.Cairo


-- for noCompletion
        -- <> Options.Applicative.value "/tmp"
import System.Console.Haskeline
import Control.Lens ((^.), view)

-- Repline is a wrapper (suppposedly more advanced) around haskeline
-- for now we focus on the simple usecase with repline
-- import System.Console.Repline
import MptcpAnalyzer.Pcap ()
import Pipes hiding (Proxy)
import System.Process hiding (runCommand)
import Distribution.Simple.Utils (withTempFileEx)
import Distribution.Compat.Internal.TempFile (openTempFile)


data Severity = TraceS | DebugS | InfoS | ErrorS deriving (Read, Show, Eq)

data CLIArguments = CLIArguments {
  _input :: Maybe FilePath
  , version    :: Bool  -- ^ to show version
  , cacheDir    :: Maybe FilePath -- ^ Folder where to log files
  , logLevel :: Severity   -- ^ what level to use to parse
  , extraCommands :: [String]  -- ^ commands to run on start
  }


loggerName :: String
loggerName = "main"


-- noCompletion
-- type CompletionFunc (m :: Type -> Type) = (String, String) -> m (String, [Completion])
-- https://hackage.haskell.org/package/optparse-applicative-0.15.1.0/docs/Options-Applicative.html#t:Parser
-- optparse :: MonadIO m => Parser a -> CompletionFunc m
-- completeFilename
-- listFiles
-- autocompletion for optparse
-- https://github.com/sdiehl/repline/issues/32
-- data Parser a
--   = NilP (Maybe a)
--   | OptP (Option a)
--   | forall x . MultP (Parser (x -> a)) (Parser x)
--   | AltP (Parser a) (Parser a)
--   | forall x . BindP (Parser x) (x -> Parser a)
-- generateCompleter :: MonadIO m => Parser a -> CompletionFunc m
-- generateCompleter (NilP _) = noCompletion
-- -- mapParser looks cool
-- -- OpT should have optProps and optMain
-- -- en fait c'est le optReader qui va decider de tout
-- -- todo we should react depending on ParseError
-- -- CompletionResult
-- generateCompleter (OptP opt) = noCompletion

plotParserGeneric :: Parser CommandArgs
plotParserGeneric = ArgsPlotGeneric 
      <$> optional (strOption
      ( long "out" <> short 'o'
      <> help "Name of the output plot."
      <> metavar "OUT" ))
    -- <*> optional ( strOption
      -- ( long "title" <> short 't'
      -- <> help "Overrides the default plot title."
      -- <> metavar "TITLE" ))
    -- <*> optional (switch
      -- ( long "primary"
      -- <> help "Copy to X clipboard, requires `xsel` to be installed"
      -- ))
    <*> optional ( strOption
      ( long "title" <> short 't'
      <> help "Overrides the default plot title."
      <> metavar "TITLE" ))
    <*> (switch
      ( long "display"
      <> help "Uses xdg-open to display plot"
      ))
      <*> plotParserSpecific

plotinfoParserGeneric :: ParserInfo CommandArgs
plotinfoParserGeneric = info (plotParserGeneric)
  ( progDesc "Generate a plot"
  )

plotParserSpecific :: Parser ArgsPlots
plotParserSpecific =
  subparser (
    command "tcp" (piPlotStreamParser ["tcpseq"])
    <> command "mptcp" (piPlotStreamParser ["tcpseq"])
   )

    -- <*> commandGroup "Loader commands"
    -- <> command "load-csv" CL.loadCsvOpts

startupParser :: Parser CLIArguments
startupParser = CLIArguments
      <$> optional ( strOption
          ( long "load"
          <> short 'l'
         <> help "Either a pcap or a csv file (in good format).\
                 \When a pcap is passed, mptcpanalyzer will look for a its cached csv.\
                 \If it can't find one (or with the flag --regen), it will generate a \
                 \csv from the pcap with the external tshark program."
         <> metavar "INPUT_FILE" ))
      <*> switch (
          long "version"
          <> help "Show version"
          )
      <*> optional ( strOption
          ( long "cachedir"
         <> help "mptcpanalyzer creates a cache of files in the folder \
            \$XDG_CACHE_HOME/mptcpanalyzer"
         -- <> showDefault
         -- <> Options.Applicative.value "/tmp"
         <> metavar "CACHEDIR" ))
      <*> option auto
          ( long "log-level"
         <> help "Log level"
         <> showDefault
         <> Options.Applicative.value InfoS
         <> metavar "LOG_LEVEL" )
      -- optional arguments
      <*> many ( argument str (
            metavar "COMMANDS..."
        ))


opts :: ParserInfo CLIArguments
opts = info (startupParser <**> helper)
  ( fullDesc
  <> progDesc "Tool to provide insight in MPTCP (Multipath Transmission Control Protocol)\
              \performance via the generation of stats & plots"
  <> header "hello - a test for optparse-applicative"
  <> footer "You can report issues/contribute at https://github.com/teto/mptcpanalyzer"
  )


-- https://github.com/sdiehl/repline/issues/32

-- just for testing, to remove afterwards
defaultPcap :: FilePath
defaultPcap = "examples/client_2_filtered.pcapng"

promptSuffix :: String
promptSuffix = "> "

-- alternatively could modify defaultPrefs
defaultParserPrefs :: ParserPrefs
defaultParserPrefs = prefs showHelpOnEmpty
-- {
--     prefShowHelpOnError = True
--     }

main :: IO ()
main = do

  cacheFolderXdg <- getXdgDirectory XdgCache "mptcpanalyzer2"
  -- TODO check if creation fails ?
  -- Create cache if doesn't exist
  doesDirectoryExist cacheFolderXdg >>= \case
      True -> putStrLn ("cache folder already exists" ++ show cacheFolderXdg)
      False -> createDirectory cacheFolderXdg

  let myState = MyState {
    _stateCacheFolder = cacheFolderXdg,
    _loadedFile = Nothing,
    _prompt = promptSuffix
  }

  options <- execParser opts

  putStrLn "Commands"
  print $ extraCommands options

  let haskelineSettings = defaultSettings {
      historyFile = Just $ cacheFolderXdg </> "history"
      }
  let
    cacheConfig :: CacheConfig
    cacheConfig = CacheConfig {
      cacheFolder = cacheFolderXdg
      , cacheEnabled = True
    }

  _ <- runInputT haskelineSettings $
          runFinal @(InputT IO)
          $ P.embedToFinal . P.runEmbedded lift
          $ P.runState myState
          $ runCache cacheConfig
          $ runLogAction @IO logStringStdout (inputLoop (extraCommands options))
  putStrLn "Thanks for flying with mptcpanalyzer"


-- |Global parser: contains every available command
-- TODO for some commands we could factorize the preprocessing eg check a file
-- was pre-loaded
-- aka check the if loadedFile was loaded
-- one can create groups with <|> subparser
mainParser :: Parser CommandArgs
mainParser = subparser (
    commandGroup "Loader commands"
    <> command "load-csv" CL.loadCsvOpts
    <> command "load-pcap" CL.loadPcapOpts
    <> commandGroup "TCP commands"
    <> command "tcp-summary" CLI.tcpSummaryOpts
    <> command "list-tcp" CLI.listTcpOpts
    <> commandGroup "MPTCP commands"
    <> command "list-mptcp" CLI.listMpTcpOpts
    <> command "export" CLI.parseExportOpts
    <> commandGroup "TCP plots"
    -- TODO here we should pass a subparser
    -- <> subparser (
    <> command "plot" Main.plotinfoParserGeneric
    -- Plots.piPlotTcpAttr
      -- )
    -- <> command "help" CLI.listMpTcpConnectionsCmd
    )


-- |Main parser
mainParserInfo :: ParserInfo CommandArgs
mainParserInfo = info (mainParser <**> helper)
  ( fullDesc
  <> progDesc "Tool to provide insight in MPTCP (Multipath Transmission Control Protocol)\
              \performance via the generation of stats & plots"
  <> header "hello - a test for optparse-applicative"
  <> footer "You can report issues/contribute at https://github.com/teto/mptcpanalyzer"
  )



-- printHelp :: P.Members '[Log String] r => [String] -> Sem r CMD.RetCode
-- -- printHelp :: [String] -> 
-- printHelp _ = logInfo "hello" >> return CMD.Continue

-- getHelp :: String
-- getHelp =
--     HM.foldrWithKey printCmdHelp "Available commands:\n" commands
--   where
--     printCmdHelp k _ accum = accum ++ "\n- " ++ k

-- liftIO $ putStrLn doPrintHelp >> 

-- runCommand :: CommandArgs -> CMD.RetCode
runCommand, runPlotCommand :: Members '[Log String, Cache, P.State MyState, P.Embed IO] r => CommandArgs -> Sem r CMD.RetCode
runCommand args@ArgsLoadPcap{} = CL.loadPcap args
runCommand args@ArgsLoadCsv{} = CL.loadCsv args
runCommand args@ArgsParserSummary{} = CLI.tcpSummary args
runCommand args@ArgsListSubflows{} = CLI.listSubflowsCmd args
runCommand args@ArgsListTcpConnections{} = CLI.listTcpConnectionsCmd args
runCommand args@ArgsListMpTcpConnections{} = CLI.listMpTcpConnectionsCmd args
runCommand args@ArgsExport{} = CLI.cmdExport args
runCommand args@ArgsPlotGeneric{} = runPlotCommand args


-- |Command specific to plots
-- TODO these should return a plot instead of a generated file so that one can overwrite the title
runPlotCommand (ArgsPlotGeneric mbOut _mbTitle displayPlot specificArgs ) = do
    -- tempPath <- embed $ withTempFileEx opts "/tmp" "plot.png" $ \tmpPath hd -> do
    -- file is not removed afterwards
    (tempPath, handle) <- P.embed $ openTempFile "/tmp" "plot.png"
    case specificArgs of
      (ArgsPlotTcpAttr pcapFilename streamId attr mbDest) -> do
        let destinations = fromMaybe [RoleClient, RoleServer] (fmap (\x -> [x]) mbDest)
        res <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcapFilename streamId
        fmap Plots.cmdPlotTcpAttribute specificArgs tempPath handle res

      (ArgsPlotMptcpAttr filePath streamId attr mbDest) -> do
        let destinations = fromMaybe [RoleClient, RoleServer] (fmap (\x -> [x]) mbDest)
        buildAFrameFromStreamIdMptcp
        Plots.cmdPlotTcpAttribute specificArgs tempPath handle

    _ <- P.embed $ case mbOut of
            -- user specified a file move the file
            -- outFilename = fromMaybe tempPath mbOut
            Just outFilename -> renameFile tempPath outFilename
            Nothing -> return ()
    if displayPlot then do
        let
          createProc :: CreateProcess
          createProc = proc "xdg-open" [ tempPath ]

        (_, _, mbHerr, ph) <- P.embed $  createProcess createProc
        exitCode <- P.embed $ waitForProcess ph
        return Continue

    else
      return Continue
runPlotCommand _ = error "Should not happen, file a bug report"



-- TODO use genericRunCommand
runIteration :: Members '[Log String, Cache, P.State MyState, P.Embed IO] r => Maybe String -> Sem r CMD.RetCode
runIteration fullCmd = do
    cmdCode <- case fmap Prelude.words fullCmd of
        Nothing -> do
          log "please enter a valid command, see help"
          return CMD.Continue
        Just args -> do
          -- TODO parse
          let parserResult = execParserPure defaultParserPrefs mainParserInfo args
          case parserResult of
            (Failure failure) -> do
                -- last arg is progname
                let (h, exit) = renderFailure failure "prompt>"
                log $ h
                log $ "Passed args " ++ show args
                return $ CMD.Error $ "could not parse: " ++ show failure
            (CompletionInvoked _compl) -> return CMD.Continue
            (Success parsedArgs) -> runCommand parsedArgs

    case cmdCode of
        CMD.Exit -> log "Exiting" >> return CMD.Exit
        CMD.Error msg -> do
          log $ "Last command failed with message:\n" ++ show msg
          return $ CMD.Error msg
        behavior -> return behavior

-- | Main loop of the program, will run commands in turn
-- TODO turn it into a library
-- [P.Final (InputT IO), Log, Cache, P.State MyState, P.Embed IO] ()
-- , P.Embed IO
inputLoop :: Members '[Log String, Cache, P.State MyState, P.Embed IO, P.Final (InputT IO)] r => [String] -> Sem r ()
-- inputLoop (xs:rest) = pure ()
inputLoop args =
  go args
  where
    go :: Members '[Log String, Cache, P.State MyState, P.Embed IO, P.Final (InputT IO)] r => [String] -> Sem r ()
    go (xs:rest) = runIteration (Just xs) >>= \case
        CMD.Exit -> log "Exiting"
        _ -> do
          log $ "Last command failed with message:\n"
          inputLoop rest
    go [] = do
      s <- P.get
      minput <- P.embedFinal $ getInputLine (view prompt s)
      runIteration minput >>= \case
        CMD.Exit -> log "Exiting"
        -- _ -> pure ()
        _ -> inputLoop []

