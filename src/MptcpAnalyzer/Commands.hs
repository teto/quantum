module MptcpAnalyzer.Commands
where
import Polysemy (Sem, Members, makeSem, interpret)
import qualified Polysemy.Embed as P
import qualified Polysemy.State as P
import Colog.Polysemy (Log)

import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Commands.Utils (RetCode(..))
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Definitions
import qualified MptcpAnalyzer.Commands.Load as CL
import qualified MptcpAnalyzer.Commands.List as CL


-- data Command m a where
--   LoadCsv :: CL.ArgsLoadPcap -> Command m RetCode
  -- LoadPcap :: ArgsLoadPcap -> Command m ()
  -- PrintHelp :: ParserArgsLoadCsv -> Command m ()

-- makeSem ''Command


printHelpTemp :: Members '[Log String, Cache, P.Embed IO] r => Sem r RetCode
printHelpTemp = do
  P.embed $ putStrLn "temporary help"
  return Continue

-- TODO
-- this should be a polysemy reinterpreter ?
runCommand :: Members '[Log String, P.State MyState, Cache, P.Embed IO] r => Sem (Command : r) a -> Sem r a
runCommand = interpret $ \case
    LoadCsv args -> CL.loadCsv args
    LoadPcap args -> CL.loadPcap args
    PrintHelp  -> printHelpTemp
    ListTcpConnections  args -> CL.listTcpConnections args
    TcpSummary  args -> CL.tcpSummary args
    -- (LogInfo stringToLog) -> embed $ putStrLn stringToLog)
