module Commands.Commands
where
import Polysemy (Sem, Members, runM, runFinal, Final, makeSem, interpret)
import qualified Polysemy.Embed as P
import Colog.Polysemy (Log, log, runLogAction)

import Commands.Utils (RetCode)
import MptcpAnalyzer.Cache
import qualified Commands.Load as CL (ArgsLoadPcap, loadCsv)


data Command m r where
  LoadCsv :: CL.ArgsLoadPcap -> Command m RetCode
  -- LoadPcap :: ArgsLoadPcap -> Command m ()
  -- PrintHelp :: ParserArgsLoadCsv -> Command m ()

makeSem ''Command


-- TODO
runCommand :: Members '[Log String, Cache, P.Embed IO] r => Sem (Command ': r) a -> Sem r a
runCommand = interpret $ \case
    LoadCsv args -> CL.loadCsv args
    -- (LogInfo stringToLog) -> embed $ putStrLn stringToLog)
