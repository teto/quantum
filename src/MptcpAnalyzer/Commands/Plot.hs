{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Commands.Plot
where

-- import Graphics.Vega.VegaLite
-- import qualified Graphics.Vega.VegaLite as VL
import MptcpAnalyzer.Types
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Loader

import Prelude hiding (filter, lookup, repeat, log)
import Options.Applicative
import Polysemy
-- import Diagrams.Backend.Rasterific
-- import Diagrams (dims2D, width, height)
import Frames

-- import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
-- import Graphics.Rendering.Chart.Easy

import Graphics.Rendering.Chart.Easy hiding (argument)
import Graphics.Rendering.Chart.Backend.Cairo
import Data.Word (Word8, Word16, Word32, Word64)

-- import Prices(prices,mkDate,filterPrices)
-- from package 'time'
-- import Data.Time.LocalTime

import Data.Text (Text)
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
import Data.Foldable (toList)


data PlotTypes = PlotTcpAttribute {
    pltAttrField :: Text
    -- syndrop => drop syn packets
    -- Drops first 3 packets of the dataframe assuming they are syn
  }

-- data PlotSettings =  PlotSettings {
--   }
-- Plot MPTCP subflow attributes over time

piPlotParserTcpAttr :: Parser PlotTypes
piPlotParserTcpAttr = PlotTcpAttribute <$> argument str
      ( help "Choose an mptcp attribute to plot"
      <> metavar "FIELD" )

piPlotTcpAttr :: ParserInfo CommandArgs
piPlotTcpAttr = info (plotParser)
  ( progDesc "Generate a plot"
  )

-- plotSubparser :: Parser PlotTypes
-- plotSubparser = 

piPlot :: ParserInfo CommandArgs
piPlot = info (plotParser)
  ( progDesc "Generate a plot"
  )

-- |Options that are available for all parsers
-- plotParserGenericOptions 

plotParser :: Parser CommandArgs
plotParser = ArgsPlotTcpAttr <$>
      -- this ends up being not optional !
      strArgument (
          metavar "PCAP"
          <> help "File to analyze"
      )
      <*> argument readStreamId (
          metavar "STREAM_ID"
          <> help "Stream Id (tcp.stream)"
      )
      -- TODO ? if nothing prints both directions
      <*> optional (argument readConnectionRole (
          metavar "Destination"
        -- <> Options.Applicative.value RoleServer
        <> help ""
      ))
      <*> optional (strOption
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
    <*> (switch
      ( long "display"
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

-- | A typeclass abstracting the functions we need
-- to be able to plot against an axis of type a
-- class Ord a => PlotValue a where
--     toValue  :: a -> Double
--     fromValue:: Double -> a
--     autoAxis :: AxisFn a

-- instance RealFloat Word32 where

instance PlotValue Word32 where
    toValue  = fromIntegral
    fromValue = truncate . toRational
        -- autoAxis = autoScaledAxis def
    -- autoScaledAxis def
    -- autoAxis = autoScaledIntAxis def
    autoAxis   = autoScaledIntAxis defaultIntAxis

-- called PlotTcpAttribute in mptcpanalyzer
-- todo pass --filterSyn Args fields
-- TODO filter according to destination
cmdPlotTcpAttribute :: Members [Log String,  P.State MyState, Cache, Embed IO] m => CommandArgs -> Sem m RetCode
cmdPlotTcpAttribute args = do
  let
    cacheId :: CacheId
    cacheId = CacheId [pcapFilename]  "" ""
  -- res <- getCache cacheId
  res <- loadPcapIntoFrame defaultTsharkPrefs pcapFilename
  ret <- case res of
    Left err -> do
        log $ "Not found in a cache" ++ (show cacheId)
        return CMD.Continue
    Right frame -> do
      -- TODO load streamId from command
      -- (plotTcpStreamId args)
      case getTcpFrame frame tcpStreamId of
        -- log "error could not get " >>
        Left err -> return $ CMD.Error "error could not get "

        -- inCore converts into a producer
        -- TODO save the file
        Right tcpFrame -> do
          let
            frame2 = addRole (ffTcpFrame tcpFrame) (ffTcpCon tcpFrame)
          embed $ toFile def "example2_big.png" $ do
              -- layoutlr_title .= "Tcp Sequence number"
              -- layoutlr_left_axis . laxis_override .= axisGridHide
              -- layoutlr_right_axis . laxis_override .= axisGridHide
              -- TODO generate for mptcp plot
              plot (line "price 1" [ [ (d,v) | (d,v) <- zip timeData seqData ] ])
              -- plotRight (line "price 2" [ [ (d,v) | (d,_,v) <- prices'] ])
          let
            createProc :: CreateProcess
            createProc = proc "xdg-open" [ "example2_big.png"]
          (_, _, mbHerr, ph) <- embed $  createProcess createProc
          exitCode <- embed $ waitForProcess ph
          -- TODO launch xdg-open
          return Continue
          where
            seqData = toList $ view tcpSeq <$> (ffTcpFrame tcpFrame)
            timeData = toList $ view relTime <$> (ffTcpFrame tcpFrame)
  return ret
  where
    tcpStreamId = plotStreamId args
    pcapFilename = plotFilename args
