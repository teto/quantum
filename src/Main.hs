{-|
Description : Mptcpanalyzer
Maintainer  : matt
Stability   : testing
Portability : Linux

TemplateHaskell for Katip :(
-}
{-# LANGUAGE OverloadedStrings #-}
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
import Prelude hiding (concat, init)
import Options.Applicative
-- for monadmask
import Control.Monad.Catch
import qualified Data.Map         as HM
import Commands.Utils (RetCode(..), CommandCb, DefaultMembers)
import qualified Commands.Utils as CMD
import Commands.List
import Commands.Load

-- Member, , Embed 
import Polysemy (Sem, Members, runM, runFinal, Final)
import qualified Polysemy as P
import Polysemy.Reader as P
import qualified Polysemy.State as P
import qualified Polysemy.Embed as P
-- import qualified Polysemy.Output as P
-- import qualified Polysemy.Trace as P

import Mptcp.Logging (logInfo, logToIO, Severity(..))
import Mptcp.Logging
import Mptcp.Cache

-- for noCompletion
import System.Console.Haskeline
import Utils
import Control.Lens ( (^.), view, set)

-- Repline is a wrapper (suppposedly more advanced) around haskeline
-- for now we focus on the simple usecase with repline
-- import System.Console.Repline
import Pcap ()
import Mptcp.Cache (runCache,)
-- import System.Environment.Blank   (getEnvDefault)
-- import           Frames
import Pipes hiding (Proxy)


-- newtype MyStack m a = MyStack {
--     unAppT :: StateT MyState m a
-- } deriving (Monad, Applicative, Functor
--     , MonadIO
--     -- , Cache
--     -- , MonadReader MyState m
--     , MonadState MyState
--     , MonadThrow
--     , MonadCatch
--     , MonadMask
--     )

data CLIArguments = CLIArguments {
  _input :: Maybe FilePath
  , version    :: Bool  -- ^ to show version
  , cacheDir    :: Maybe FilePath -- ^ Folder where to log files
  , logLevel :: Severity   -- ^ what level to use to parse
  , extraCommands :: [String]  -- ^ commands to run on start
  }


loggerName :: String
loggerName = "main"


data Sample = Sample
  { hello      :: String
  , quiet      :: Bool
  , enthusiasm :: Int }


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



-- loadCsv :: (Cache m, MonadIO m, KatipContext m) => FilePath -> m PcapFrame
-- loadCsv csvFile = do
--     frame <- liftIO $ loadRows csvFile
--     return frame


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

  _ <- runInputT haskelineSettings $
          runFinal @(InputT IO) 
          $ P.embedToFinal . P.runEmbedded lift
          $ P.runState myState
          $ runCache
          $ logToIO inputLoop
  putStrLn "Thanks for flying with mptcpanalyzer"

-- , P.Embed IO
testLoop :: Members '[ Log, P.Embed IO, Final (InputT IO)] r => Sem r ()
testLoop = do
  _minput <- P.embedFinal $ getInputLine "prompt>"
  logInfo "test"
  return ()

-- type CommandList m = HM.Map String (CommandCb m)
-- commands :: HM.Map String CommandCb
-- commands :: Members DefaultMembers r => HM.Map String ([String] -> Sem r CMD.RetCode)
commands :: Members DefaultMembers r => HM.Map String ([String] -> Sem r CMD.RetCode)
commands = HM.fromList [
    -- ("load", loadPcap)
    ("load_csv", loadCsv)
    -- , ("list_tcp", listTcpConnections)
    , ("help", printHelp)
    -- , ("list_mptcp", listMpTcpConnections)
    ]


printHelp :: P.Members '[Log] r => [String] -> Sem r CMD.RetCode
-- printHelp :: [String] -> 
printHelp _ = logInfo "hello" >> return CMD.Continue

-- getHelp :: String
-- getHelp =
--     HM.foldrWithKey printCmdHelp "Available commands:\n" commands
--   where
--     printCmdHelp k _ accum = accum ++ "\n- " ++ k

-- liftIO $ putStrLn doPrintHelp >> 

-- | Main loop of the program, will run commands in turn
-- TODO turn it into a library
-- [P.Final (InputT IO), Log, Cache, P.State MyState, P.Embed IO] ()
-- , P.Embed IO
inputLoop :: Members  [Log, Cache, P.State MyState, P.Embed IO, P.Final (InputT IO)] r => Sem r ()
inputLoop = do
    s <- P.get
    minput <- P.embedFinal $ getInputLine (view prompt s)
    cmdCode <- case fmap Prelude.words minput of
        Nothing -> do
          logInfo "please enter a valid command, see help"
          return CMD.Continue
        Just [] -> return $ CMD.Error "Please enter a command"

        Just (commandStr:args) -> do
          let cmd = HM.lookup commandStr commands
          case cmd of
            Nothing -> return $ CMD.Error "Unknown command"
            Just cb -> cb args

    case cmdCode of
        CMD.Exit -> return ()
        CMD.Error msg -> do
          logInfo $ "Last command failed with message:\n" ++ show msg
          inputLoop
        _behavior -> inputLoop


-- TODO pass the command
-- runCommand :: CommandCb -> [String] -> Sem r CMD.RetCode
-- runCommand callback args = do
--     callback args


data SimpleData = SimpleData {
      mainStr :: String
      , optionalHello      :: String
    }
