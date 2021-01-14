module MptcpAnalyzer.Commands.Plot
where

import Prelude hiding (filter, lookup, repeat)
import Graphics.Vega.VegaLite
import qualified Graphics.Vega.VegaLite as VL
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Commands.Utils
import MptcpAnalyzer.Cache
import Options.Applicative
import Polysemy
import Colog.Polysemy (Log, log)


plotParser :: Parser ArgsPlot
plotParser = ArgsPlot <$>
         strOption
          ( long "out" <> short 'o'
         <> help "Name of the output plot."
         <> metavar "OUT" )
        <*> optional ( strOption
          ( long "title" <> short 't'
         <> help "Overrides the default plot title."
         <> metavar "TITLE" ))
        <*> optional ( switch
          ( long "primary"
         <> help "Copy to X clipboard, requires `xsel` to be installed"
         ))


{-
  -
P.State MyState,
-}
cmdPlot :: Members [Log String,  Cache, Embed IO] m => ArgsPlot -> Sem m RetCode
cmdPlot args = do
  return Continue

-- parserPlot
-- toVegaLite [ bkg, cars, mark Circle [MTooltip TTEncoding], enc [] ]
