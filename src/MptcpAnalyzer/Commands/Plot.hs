module MptcpAnalyzer.Commands.Plot
where

-- import Graphics.Vega.VegaLite
-- import qualified Graphics.Vega.VegaLite as VL
import MptcpAnalyzer.Types
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD

import Prelude hiding (filter, lookup, repeat, log)
import Options.Applicative
import Polysemy
-- import Diagrams.Backend.Rasterific
import Diagrams (dims2D, width, height)
import Frames
import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
import Graphics.Rendering.Chart.Easy
import qualified Pipes as P
import qualified Pipes.Prelude as P
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)

plotParser :: Parser CommandArgs
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


-- {- TODO a generic version
-- P.State MyState,
-- -}
-- cmdPlot :: Members [Log String,  Cache, Embed IO] m => ArgsPlot -> Sem m RetCode
-- cmdPlot args = do
--   return Continue

-- called PlotTcpAttribute in mptcpanalyzer
-- todo pass --filterSyn Args fields
cmdPlotTcpAttribute :: Members [Log String,  Cache, Embed IO] m => CommandArgs -> Sem m RetCode
cmdPlotTcpAttribute args = do
  state <- P.get
  let loadedPcap = view loadedFile state
  case loadedPcap of
    Nothing -> do
      log "please load a pcap first"
      return CMD.Continue
    Just frame -> do
      case getTcpFrame (plotTcpStreamId args) of
        Left err -> log "ERRORO"
        -- inCore converts into a producer
        Right tcpFrame -> inCore ( ffTcpFrame tcpFrame)
  -- return Continue
  -- tcpSeq
  ldlData <- runSafeT . P.toListM $ triglyData P.>-> P.map rcast
  let d = chart2diagram $ mkPlots ldlData
      sz = dims2D (width d) (height d)
  renderRasterific "plot.png" sz d


-- parserPlot
-- toVegaLite [ bkg, cars, mark Circle [MTooltip TTEncoding], enc [] ]
