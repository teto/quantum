module MptcpAnalyzer.Commands.Plot
where

import Prelude hiding (filter, lookup, repeat)
-- import Graphics.Vega.VegaLite
-- import qualified Graphics.Vega.VegaLite as VL
import MptcpAnalyzer.Commands.Types
import MptcpAnalyzer.Cache

import Options.Applicative
import Polysemy
import Colog.Polysemy (Log, log)
import Diagrams.Backend.Rasterific
import Diagrams (dims2D, width, height)
import Frames
import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
import Graphics.Rendering.Chart.Easy


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


{- TODO a generic version
P.State MyState,
-}
cmdPlot :: Members [Log String,  Cache, Embed IO] m => ArgsPlot -> Sem m RetCode
cmdPlot args = do
  return Continue

-- called PlotTcpAttribute in mptcpanalyzer
-- todo pass --filterSyn Args fields
cmdPlotTcpAttribute :: Members [Log String,  Cache, Embed IO] m => ArgsPlot -> Sem m RetCode
cmdPlot args = do
  return Continue
  let d = chart2diagram $ mkPlots ldlData
      sz = dims2D (width d) (height d)
  renderRasterific "plot.png" sz d


-- parserPlot
-- toVegaLite [ bkg, cars, mark Circle [MTooltip TTEncoding], enc [] ]
