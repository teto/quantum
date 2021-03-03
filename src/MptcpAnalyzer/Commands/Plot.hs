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
-- import Diagrams (dims2D, width, height)
import Frames

-- import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
-- import Graphics.Rendering.Chart.Easy

import Graphics.Rendering.Chart.Easy
import Graphics.Rendering.Chart.Backend.Cairo

-- import Prices(prices,mkDate,filterPrices)
-- from package 'time'
-- import Data.Time.LocalTime

import qualified Pipes as P
import qualified Pipes.Prelude as P
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)
-- import Diagrams.Prelude
-- import Diagrams.Backend.SVG.CmdLine
import System.Process
import System.Exit
-- import Data.Time.LocalTime

piPlot :: ParserInfo CommandArgs
piPlot = info (plotParser)
  ( progDesc "Generate a plot"
  )

plotParser :: Parser CommandArgs
plotParser = ArgsPlot <$>
      -- this ends up being not optional !
      optional (strOption
      ( long "out" <> short 'o'
      <> help "Name of the output plot."
      <> metavar "OUT" ))
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

-- prices' :: [(LocalTime, Double, Double)]
-- prices' = filterPrices prices (mkDate 1 1 2005) (mkDate 31 12 2006)
prices' :: [(Int, Int)]
-- prices' = zip [1..30] [10,12..40]
prices' = [ (4, 2), (6, 9)]

-- openPicture :: FilePath -> 

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
        -- TODO save the file
        Right tcpFrame -> do
          embed $ toFile def "example2_big.png" $ do
              -- layoutlr_title .= "Tcp Sequence number"
              -- layoutlr_left_axis . laxis_override .= axisGridHide
              -- layoutlr_right_axis . laxis_override .= axisGridHide
              plot (line "price 1" [ [ (d,v) | (d,v) <- prices'] ])
              -- plotRight (line "price 2" [ [ (d,v) | (d,_,v) <- prices'] ])
          let
            createProc :: CreateProcess
            createProc = proc "xdg-open" [ "example2_big.png"]
          (_, _, mbHerr, ph) <- embed $  createProcess createProc
          exitCode <- embed $ waitForProcess ph
          -- TODO launch xdg-open
          return Continue
          where
            seqData = view tcpSeq <$> (ffTcpFrame tcpFrame)
  return ret
  where
    tcpStreamId = StreamId 0

