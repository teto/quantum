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

import System.FilePath
import System.Directory
import Prelude hiding (concat, init, log)
import Options.Applicative
import Colog.Core.IO (logStringStdout)
import Colog.Polysemy (Log, log, runLogAction)
-- for monadmask
-- import Control.Monad.Catch
-- import qualified Data.Map         as HM
import MptcpAnalyzer.Commands.Utils (RetCode(..), )
import qualified MptcpAnalyzer.Commands.Utils as CMD
import MptcpAnalyzer.Commands
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Commands.List as CLI
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

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Definitions

-- for noCompletion
import System.Console.Haskeline
import Control.Lens ((^.), view)

-- Repline is a wrapper (suppposedly more advanced) around haskeline
-- for now we focus on the simple usecase with repline
-- import System.Console.Repline
import MptcpAnalyzer.Pcap ()
import Pipes hiding (Proxy)


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

sample :: Parser CLIArguments
sample = CLIArguments
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
      <*> some ( argument str (
            metavar "COMMANDS..."
        ))


opts :: ParserInfo CLIArguments
opts = info (sample <**> helper)
  ( fullDesc
  <> progDesc "Tool to provide insight in MPTCP (Multipath Transmission Control Protocol)\
              \performance via the generation of stats & plots"
  <> header "hello - a test for optparse-applicative"
  <> footer "You can report issues/contribute at https://github.com/teto/mptcpanalyzer"
  )

-- https://github.com/sdiehl/repline/issues/32
-- data Parser a
--   = NilP (Maybe a)
--   | OptP (Option a)
--   | forall x . MultP (Parser (x -> a)) (Parser x)
--   | AltP (Parser a) (Parser a)
--   | forall x . BindP (Parser x) (x -> Parser a)

-- TODO change
-- type Repl a = HaskelineT IO a

-- ini :: Repl ()
-- ini = liftIO $ putStrLn "Welcome!"

-- -- Commands
-- mainHelp :: [String] -> Repl ()
-- mainHelp args = liftIO $ print $ "Help: " ++ show args

-- say :: [String] -> Repl ()
-- say args = do
--   _ <- liftIO $ system $ "cowsay" ++ " " ++ (unwords args)
--   return ()

-- options :: [(String, [String] -> Repl ())]
-- options = [
--     ("help", mainHelp)  -- :help
--   , ("say", say)    -- :say
--   , ("load", cmdLoadPcap)    -- :say
--   ]
-- repl :: IO ()
-- repl = evalRepl (pure ">>> ") cmd options Nothing (Word completer) ini
-- Evaluation : handle each line user inputs

-- cmd :: String -> Repl ()
-- cmd input = liftIO $ print input

-- -- Tab Completion: return a completion for partial words entered
-- completer :: Monad m => WordCompleter m
-- completer n = do
--   let names = ["load", "listConnections", "listMptcpConnections"]
--   return $ filter (isPrefixOf n) names

-- data CompleterStyle m , I can use a Custom one
-- mainRepline :: IO ()
-- mainRepline = evalRepl (pure ">>> ") cmd Main.options Nothing (Word Main.completer) ini


-- data CommandEnum = 
--   LoadCsv CL.ArgsLoadPcap
--   | LoadPcap CL.ArgsLoadPcap

-- data CommandParser  = CommandParser {}
-- newtype ArgsOptions = ArgsOptions
--   { optCommand :: CommandEnum
--   }

-- ( progDesc "Load a CSV file" )
-- TODO use this command parser
commandParser :: Members '[ Command ] r => Parser (Sem r CMD.RetCode)
commandParser = subparser (
    command "loadCsv" CL.loadCsvOpts
    <> command "load-pcap" CL.loadPcapOpts
    <> command "tcp-summary" CLI.tcpSummaryOpts
    )

-- just for testing, to remove afterwards
defaultPcap :: FilePath
defaultPcap = "examples/client_2_filtered.pcapng"

promptSuffix :: String
promptSuffix = "> "

main :: IO ()
main = do

  cacheFolderXdg <- getXdgDirectory XdgCache "mptcpanalyzer2"
  -- TODO check if creation fails ?
  -- Create cache if doesn't exist
  doesDirectoryExist cacheFolderXdg >>= \case
      True -> putStrLn ("cache folder already exists" ++ show cacheFolderXdg)
      False -> createDirectory cacheFolderXdg

  let myState = MyState {
    _cacheFolder = cacheFolderXdg,
    _loadedFile = Nothing,
    _prompt = promptSuffix
  }

  options <- execParser opts

  putStrLn "Commands"
  print $ extraCommands options

  let haskelineSettings = defaultSettings {
      historyFile = Just $ cacheFolderXdg </> "history"
      }

  -- TODO if there is an exit, exit, should be a fold ?
  -- mapM_ (runApp myState . words ) (extraCommands options)
  -- runEmbedded  liftIO
-- $ P.embed ( pure 4 :: IO Int)
-- $ P.runEmbedded liftIO

  -- _ <- P.runM
  --       $ runCache
  --       $ P.runState myState
  --         $ runLogAction @IO logStringStdout
  --       $ genericRunCommandTest ["load-csv"]


  _ <- runInputT haskelineSettings $
          runFinal @(InputT IO)
          $ P.embedToFinal . P.runEmbedded lift
          $ P.runState myState
          $ runCache
          $ runLogAction @IO logStringStdout (inputLoop (extraCommands options))
  putStrLn "Thanks for flying with mptcpanalyzer"

-- genericRunCommandTest ::  Members '[Log String, P.State MyState, Cache, P.Embed IO] r => [String] -> Sem r RetCode
-- Cache, 
genericRunCommandTest ::  Members '[Log String, P.State MyState,Cache, P.Embed IO] r => [String] -> Sem r RetCode
genericRunCommandTest _args = do
  P.embed ( pure CMD.Continue:: IO RetCode)

  -- return CMD.Continue
-- -- $ P.embed (pure Continue)
-- runApp ::  MyState -> [String] -> IO RetCode
-- runApp _state parsedCmd = 
--      return $ P.run
--         $ P.runEmbedded 
--         $ runCache
--         $ genericRunCommandTest parsedCmd

-- $ runCommandStr parsedCmd
-- $ P.runState state
-- $ runLogAction @IO logStringStdout


-- |
runCommandStr ::  Members '[Log String, Cache, P.State MyState, P.Embed IO] r => [String] -> Sem r RetCode
runCommandStr [] = return $ CMD.Error "Please enter a command"
runCommandStr (commandStr:args) = do
  case commandStr of
    "loadPcap" -> genericRunCommand CL.loadPcapOpts args
    "load-csv" -> genericRunCommand CL.loadCsvOpts args
    "list-tcp" -> genericRunCommand CLI.listTcpOpts args
    "tcp-summary" -> genericRunCommand CLI.tcpSummaryOpts args
    _ -> return $ CMD.Error $ commandStr ++ "Not implemented yet"

-- type CommandList m = HM.Map String (CommandCb m)
-- commands :: Members DefaultMembers r => HM.Map String (Sem r RetCode)
-- commands :: Members DefaultMembers r => HM.Map String  (Sem r CMD.RetCode)
-- commands = HM.fromList [
--     -- ("load", loadPcap)
--     ("load_csv", loadCsv)
--     -- , ("list_tcp", listTcpConnections)
--     , ("help", printHelp)
--     -- , ("list_mptcp", listMpTcpConnections)
--     ]


-- printHelp :: P.Members '[Log String] r => [String] -> Sem r CMD.RetCode
-- -- printHelp :: [String] -> 
-- printHelp _ = logInfo "hello" >> return CMD.Continue

-- getHelp :: String
-- getHelp =
--     HM.foldrWithKey printCmdHelp "Available commands:\n" commands
--   where
--     printCmdHelp k _ accum = accum ++ "\n- " ++ k

-- liftIO $ putStrLn doPrintHelp >> 


genericRunCommand ::  Members '[Log String, P.State MyState, Cache, P.Embed IO] r => ParserInfo (Sem (Command : r) RetCode) -> [String] -> Sem r RetCode
genericRunCommand parserInfo args = do
  let parserResult = execParserPure defaultParserPrefs parserInfo args
  case parserResult of
    (Failure failure) -> do
        log $ show failure
        return $ CMD.Error $ "could not parse: " ++ show failure
    (CompletionInvoked _compl) -> return CMD.Continue
    (Success parsedArgs) -> runCommand parsedArgs

-- | Main loop of the program, will run commands in turn
-- TODO turn it into a library
-- [P.Final (InputT IO), Log, Cache, P.State MyState, P.Embed IO] ()
-- , P.Embed IO
inputLoop :: Members '[Log String, Cache, P.State MyState, P.Embed IO, P.Final (InputT IO)] r => [String] -> Sem r ()
inputLoop initialInputs = do
  case initialInputs of
      [] -> do
          s <- P.get
          minput <- P.embedFinal $ getInputLine (view prompt s)
          runIteration minput
      (xs:rest) -> do
          runIteration $ Just xs
          inputLoop rest
      where
          runIteration fullCmd = do
              cmdCode <- case fmap Prelude.words fullCmd of
                  Nothing -> do
                    log "please enter a valid command, see help"
                    return CMD.Continue
                  Just args -> runCommandStr args

              case cmdCode of
                  CMD.Exit -> void (log "Exiting")
                  CMD.Error msg -> do
                    log $ "Last command failed with message:\n" ++ show msg
                    inputLoop []
                  _behavior -> inputLoop []

-- TODO pass the command
-- runCommand :: CommandCb -> [String] -> Sem r CMD.RetCode
-- runCommand callback args = do
--     callback args
