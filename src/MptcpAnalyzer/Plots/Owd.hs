{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Plots.Owd
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.Plots.Types
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Debug

import Prelude hiding (filter, lookup, repeat, log)
import Options.Applicative
import Polysemy
import Frames
import Frames.CSV

-- import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
-- import Graphics.Rendering.Chart.Easy

import Graphics.Rendering.Chart.Easy hiding (argument)
import Graphics.Rendering.Chart.Backend.Cairo
import Data.Word (Word8, Word16, Word32, Word64)

import Data.Text (Text)
import qualified Data.Text as T
import qualified Pipes as P
import qualified Pipes.Prelude as P
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)
import System.Process hiding (runCommand)
import System.Exit
-- import Data.Time.LocalTime
import Data.Foldable (toList)
import Data.Maybe (fromMaybe)
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Directory (renameFile)
import System.IO (Handle)
import Frames.ShowCSV (showCSV)
import qualified Data.Set as Set
import Debug.Trace


-- data PlotTypes = PlotTcpAttribute {
--     pltAttrField :: Text
--     -- syndrop => drop syn packets
--     -- Drops first 3 packets of the dataframe assuming they are syn
--   }

-- data PlotSettings =  PlotSettings {
--   }
-- Plot MPTCP subflow attributes over time

-- piPlotParserTcpAttr :: Parser PlotTypes
-- piPlotParserTcpAttr = PlotTcpAttribute <$> argument str
--       ( help "Choose an mptcp attribute to plot"
--       <> metavar "FIELD" )

-- piPlotTcpAttr :: ParserInfo CommandArgs
-- piPlotTcpAttr = info (ArgsPlotGeneric <$> plotParserOwd)
--   ( progDesc "Generate a plot"
--   )


-- |
-- @param 
piPlotTcpOwd ::  ParserInfo ArgsPlots
piPlotTcpOwd = info (plotParserOwd False)
  ( progDesc "Plot TCP attr"
  )

-- |
-- @param 
-- piPlotMptcpAttrParser ::  ParserInfo ArgsPlots
-- piPlotMptcpAttrParser = info (
--   plotParserOwd True
--   )
--   ( progDesc "Plot MPTCP attr"
--   )


-- type ValidAttributes = [String]

-- TODO pass the list of accepted attributes (so that it works for TCP/MPTCP)
plotParserOwd :: 
    -- [String]
    Bool -- ^ for mptcp yes or no
    -> Parser ArgsPlots
plotParserOwd mptcpPlot = ArgsPlotOwd <$>
      -- this ends up being not optional !
      strArgument (
          metavar "PCAP1"
          <> help "File to analyze"
      )
      <*> strArgument (
          metavar "PCAP2"
          <> help "File to analyze"
      )
      -- auto readStreamId
      <*> argument auto (
          metavar "STREAM_ID"
          <> help "Stream Id (tcp.stream)"
      )
      -- TODO validate as presented in https://github.com/pcapriotti/optparse-applicative/issues/75
      --validate :: (a -> Either String a) -> ReadM a -> ReadM a
      -- TODO ? if nothing prints both directions
      <*> optional (argument readConnectionRole (
          metavar "Destination"
        -- <> Options.Applicative.value RoleServer
        <> help ""
      ))
      <*> option auto (
          metavar "MPTCP"
        -- internal is stronger than --belive, hides from all descriptions
        <> internal
        <> Options.Applicative.value mptcpPlot
        <> help ""
      )

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

-- destinations is an array of destination
cmdPlotTcpAttribute :: Members [Log String,  P.State MyState, Cache, Embed IO] m =>
          FilePath -- ^ temporary file to save plot to
          -> Handle
          -> [ConnectionRole]
          -> FrameFiltered Packet
          -> Sem m RetCode
cmdPlotTcpAttribute tempPath _ destinations aFrame = do

-- inCore converts into a producer
  -- embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
  -- embed $ writeCSV "debug.csv" frame2
  embed $ toFile def tempPath $ do
      layout_title .= "TCP Sequence number"
      -- TODO generate for mptcp plot
      flip mapM_ destinations plotAttr

  return Continue
  where
    -- filter by dest
    frame2 = addTcpDestinationsToFrame aFrame
    plotAttr dest =
        plot (line ("TCP seq (" ++ show dest ++ ")") [ [ (d,v) | (d,v) <- zip timeData seqData ] ])
        where
          -- frameDest = ffTcpFrame tcpFrame
          frameDest = frame2
          -- frameDest = frame2
          unidirectionalFrame = filterFrame (\x -> x ^. tcpDest == dest) (ffFrame frameDest)

          seqData :: [Double]
          seqData = map fromIntegral (toList $ view tcpSeq <$> unidirectionalFrame)
          timeData = toList $ view relTime <$> unidirectionalFrame


cmdPlotTcpOwd :: Members [Log String,  P.State MyState, Cache, Embed IO] m =>
          FilePath -- ^ temporary file to save plot to
          -> Handle
          -> [ConnectionRole]
          -> FrameFiltered Packet
          -> Sem m RetCode
cmdPlotTcpOwd tempPath _ destinations aFrame = do
  log $ "plotting OWDs "
  return CMD.Continue
