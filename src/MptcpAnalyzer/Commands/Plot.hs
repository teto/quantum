module MptcpAnalyzer.Commands.Plot
where

import Prelude hiding (filter, lookup, repeat)
import Graphics.Vega.VegaLite
import qualified Graphics.Vega.VegaLite as VL
import MptcpAnalyzer.Commands.Definitions
import Options.Applicative

plotParser :: Parser ArgsPlot
plotParser = ArgsPlot <$>
        optional ( strOption
          ( long "out" <> short 'o'
         <> help "Name of the output plot."
         <> metavar "OUT" ))
        <*> optional ( strOption
          ( long "title" <> short 't'
         <> help "Overrides the default plot title."
         <> metavar "TITLE" ))
        <*> optional ( strOption
          ( long "primary"
         <> help "Copy to X clipboard, requires `xsel` to be installed"
         <> metavar "clipboard" ))



toVegaLite [ bkg, cars, mark Circle [MTooltip TTEncoding], enc [] ]
