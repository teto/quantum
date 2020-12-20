import Polysemy (Sem, Members, runM, runFinal, Final)

import Mptcp.Commands.Load (ParserArgsLoadCsv)


data Command m r where
  LoadCsv :: ParserArgsLoadCsv -> Command m ()

makeSem ''Command


-- TODO
runCommand :: Sem (Command ': r) -> Sem r a
runCommand = 

