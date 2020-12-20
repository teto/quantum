module Commands.Commands
where
import Polysemy (Sem, Members, runM, runFinal, Final)

import Commands.Utils
import Commands.Load (ParserArgsLoadCsv, loadCsv)


data Command m r where
  LoadCsv :: ArgsLoadPcap -> Command m Retcode
  -- LoadPcap :: ArgsLoadPcap -> Command m ()
  -- PrintHelp :: ParserArgsLoadCsv -> Command m ()

makeSem ''Command


-- TODO
runCommand :: Sem (Command ': r) -> Sem r RetCode
runCommand = interpret $ \case
    LoadCsv args -> loadCsv
    -- (LogInfo stringToLog) -> embed $ putStrLn stringToLog)
