-- TODO replace with colog
module Mptcp.Logging
where

import Polysemy

data Severity = TraceS | DebugS | InfoS | ErrorS deriving (Read, Show, Eq)

data Log m a where
  Log.info :: String -> Log m ()

-- generates Log.info function
makeSem ''Log

logToIO :: Member (Embed IO) r => Sem (Log ': r) a -> Sem r a
logToIO = interpret (\(Log.info stringToLog) -> embed $ putStrLn stringToLog)

