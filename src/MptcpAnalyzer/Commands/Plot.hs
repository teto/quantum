module MptcpAnalyzer.Commands.Plot
where

-- import Graphics.Vega.VegaLite
-- import qualified Graphics.Vega.VegaLite as VL
import MptcpAnalyzer.Types
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Pcap

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
import Diagrams.Prelude
import Diagrams.Backend.SVG.CmdLine

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
    <*> optional (switch
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
cmdPlotTcpAttribute :: Members [Log String,  P.State MyState, Cache, Embed IO] m => CommandArgs -> Sem m RetCode
cmdPlotTcpAttribute args = do
  state <- P.get
  let loadedPcap = view loadedFile state
  ret <- case loadedPcap of
    Nothing -> do
      log "please load a pcap first"
      return CMD.Continue
    Just frame -> do
      -- TODO load streamId from command
      -- (plotTcpStreamId args)
      case getTcpFrame frame tcpStreamId of
        -- log "error could not get " >>
        Left err -> return $ CMD.Error "error could not get "

        -- inCore converts into a producer
        Right tcpFrame -> do
          -- tcpSeq
          ldlData <- runSafeT . P.toListM $ seqData P.>-> P.map rcast

          let myCircle :: Diagram B
          myCircle = circle 1

          -- let chart2diagram = fst . runBackendR env . toRenderable . execEC

          let d = chart2diagram $ mkPlots ldlData
              sz = dims2D (width d) (height d)
          -- renderRasterific "plot.png" sz d
          return Continue
          where
            seqData = view tcpSeq <$> (ffTcpFrame tcpFrame)
  return ret
  where
    tcpStreamId = StreamId 0



-- parserPlot
-- toVegaLite [ bkg, cars, mark Circle [MTooltip TTEncoding], enc [] ]
