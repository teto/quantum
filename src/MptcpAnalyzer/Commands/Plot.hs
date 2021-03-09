{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Commands.Plot
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

-- piPlotTcpAttr :: ParserInfo CommandArgs
-- piPlotTcpAttr = info (ArgsPlotGeneric <$> plotStreamParser)
--   ( progDesc "Generate a plot"
--   )

-- plotSubparser :: Parser PlotTypes
-- plotSubparser = 

-- piPlot :: ParserInfo CommandArgs
-- piPlot = info (plotStreamParser)
--   ( progDesc "Generate a plot"
--   )

-- |Options that are available for all parsers
-- plotParserGenericOptions 

-- TODO this could be generalized ?
plotStreamParser :: Parser ArgsPlots
plotStreamParser = ArgsPlotTcpAttr <$>
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
    <*> optional ( strOption
      ( long "title" <> short 't'
      <> help "Overrides the default plot title."
      <> metavar "TITLE" ))



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
          ArgsPlots ->
          FilePath
          -> Handle
          -> Sem m RetCode
cmdPlotTcpAttribute args@ArgsPlotTcpAttr{} tempPath _ = do
  res <- loadPcapIntoFrame defaultTsharkPrefs pcapFilename
  ret <- case res of
    Left err -> do
        log $ "Could not load " ++ pcapFilename ++ " because " ++ err
        return CMD.Continue
    Right frame -> do
      case getTcpFrame frame tcpStreamId of
        -- log "error could not get " >>
        Left err -> return $ CMD.Error "error could not get "

        -- inCore converts into a producer
        Right tcpFrame -> do
          -- TODO with frame2
          -- embed $ putStrLn $ T.unpack $ showCSV frame
          embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
          embed $ writeCSV "debug.csv" frame2
          -- embed $ viewFrame frame2
          embed $ toFile def tempPath $ do
              layout_title .= "Tcp Sequence number"
              -- TODO generate for mptcp plot
              flip mapM_ destinations plotAttr

          return Continue
          where
            -- filter by dest
            frame2 = addRole (ffTcpFrame tcpFrame) (ffTcpCon tcpFrame)
            plotAttr dest =
                plot (line ("TCP seq (" ++ show dest ++ ")") [ [ (d,v) | (d,v) <- zip timeData seqData ] ])
                where
                  -- frameDest = ffTcpFrame tcpFrame
                  frameDest = frame2
                  -- frameDest = frame2
                  unidirectionalFrame = filterFrame (\x -> x ^. tcpRole == dest) frameDest

                  seqData :: [Double]
                  seqData = map fromIntegral (toList $ view tcpSeq <$> unidirectionalFrame)
                  timeData = toList $ view relTime <$> unidirectionalFrame
  return ret
  where
    tcpStreamId = plotStreamId args
    pcapFilename = plotFilename args
    destinations :: [ConnectionRole]
    destinations = fromMaybe [RoleClient, RoleServer] (fmap (\x -> [x]) $ plotDest args)
    opts :: TempFileOptions
    opts = TempFileOptions True
    cacheId :: CacheId
    cacheId = CacheId [pcapFilename]  "" ""

-- cmdPlotTcpAttribute _ _ _ = error "unsupported"
