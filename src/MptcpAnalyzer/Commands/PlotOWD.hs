{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE DataKinds   #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE PolyKinds           #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE TypeOperators       #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE TypeOperators       #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE Rank2Types          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Commands.PlotOWD
where

import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Types
import MptcpAnalyzer.Plots.Types
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Debug
import MptcpAnalyzer.Merge
-- for retypeColumn
import MptcpAnalyzer.Frames.Utils
-- for fields
import Tshark.TH2

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
import qualified Pipes as P hiding (embed)
import qualified Pipes.Prelude as P
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)
import System.Process hiding (runCommand)
import System.Exit
-- import Data.Time.LocalTime
import Data.Foldable (toList)
import Data.Maybe (fromMaybe, catMaybes)
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Directory (renameFile)
import System.IO (Handle)
import Frames.ShowCSV (showCSV)
import qualified Data.Set as Set
import Debug.Trace
import GHC.TypeLits (Symbol)

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
          metavar "STREAM_ID1"
          <> help "Stream Id (tcp.stream)"
      )
      <*> argument auto (
          metavar "STREAM_ID2"
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
      -- <*> option auto (
      --     metavar "MPTCP"
      --   -- internal is stronger than --belive, hides from all descriptions
      --   <> internal
      --   <> Options.Applicative.value mptcpPlot
      --   <> help ""
      -- )

-- called PlotTcpAttribute in mptcpanalyzer
-- todo pass --filterSyn Args fields
-- TODO filter according to destination

-- destinations is an array of destination
-- cmdPlotTcpAttribute :: Members [Log String,  P.State MyState, Cache, Embed IO] m =>
--           FilePath -- ^ temporary file to save plot to
--           -> Handle
--           -> [ConnectionRole]
--           -> FrameFiltered Packet
--           -> Sem m RetCode
-- cmdPlotTcpAttribute tempPath _ destinations aFrame = do

-- -- inCore converts into a producer
--   -- embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
--   -- embed $ writeCSV "debug.csv" frame2
--   embed $ toFile def tempPath $ do
--       layout_title .= "TCP Sequence number"
--       -- TODO generate for mptcp plot
--       flip mapM_ destinations plotAttr

--   return Continue
--   where
--     -- filter by dest
--     frame2 = addTcpDestinationsToFrame aFrame
--     plotAttr dest =
--         plot (line ("TCP seq (" ++ show dest ++ ")") [ [ (d,v) | (d,v) <- zip timeData seqData ] ])
--         where
--           -- frameDest = ffTcpFrame tcpFrame
--           frameDest = frame2
--           -- frameDest = frame2
--           unidirectionalFrame = filterFrame (\x -> x ^. tcpDest == dest) (ffFrame frameDest)

--           seqData :: [Double]
--           seqData = map fromIntegral (toList $ view tcpSeq <$> unidirectionalFrame)
--           timeData = toList $ view relTime <$> unidirectionalFrame

-- AbsTime2
-- type AbsTime2 = "absTime2" :-> Text  -- :: (Symbol, *)

-- absTime2 is problematic
-- declareColumn "absTime2" ''Text
-- declareColumn "absTimeSnd" ''Double
-- type AbsTime2 = "absTime2" :-> Text  -- :: (Symbol, *)
-- expects (Symbol, Symbol, Type)
-- type AbsTimeRenameTest =   ("absTime" :: Symbol, "absTime2", Text)

-- type RetypeMatt = [
--   ("absTime", "absTime2", Text)
--   ]

cmdPlotTcpOwd :: Members [Log String, P.State MyState, Cache, Embed IO] m =>
          FilePath -- ^ temporary file to save plot to
          -> Handle
          -> [ConnectionRole]
          -> MergedPcap
          -- -> FrameFiltered Packet
          -- -> FrameFiltered (Record RecTsharkPrefixed)
          -> Sem m RetCode
cmdPlotTcpOwd tempPath _ destinations mergedRes = do
  log $ "plotting OWDs "
  -- look at https://hackage.haskell.org/package/vinyl-0.13.0/docs/Data-Vinyl-Functor.html#t::.
  -- to see how to deal with 
  -- type (:.) f g = Compose f g
  -- let mergedRes = mergeTcpConnectionsFromKnownStreams aFrame1 processedAFrame2
  -- recMaybe
  let mbRecs = map recMaybe mergedRes
  let justRecs = catMaybes mbRecs
  -- could use showRow as well
  P.embed $ dumpRec $ head justRecs
  P.embed $ putStrLn $ "There are " ++ show (length justRecs) ++ " valid merged rows (out of " ++ show (length mergedRes) ++ " merged rows)"
  P.embed $ putStrLn $ (concat . showFields) (head justRecs)
  -- P.embed $ putStrLn $ "retyped column" ++ (concat . showFields) (newCol)


  -- mapM dumpRec mbRecs
  -- let mbRec = recMaybe mergedRes
  -- putStrLn mbRec
  -- embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
  embed $ writeDSV defaultParserOptions "debug.csv" (toFrame justRecs)
  -- embed $ writeDSV defaultParserOptions "retyped.csv" processedFrame2
  -- so for now we assume an innerJoin (but fix it later)

  return CMD.Continue
  where
    -- Maybe Record
    -- dumpRec Nothing = putStrLn "nothing"
    dumpRec x = putStrLn $ show $ x
    -- firstRes = (head justRecs)
    -- processedFrame2 =  frame2

    -- frame2 = ffFrame aFrame2

    -- processedAFrame2 :: FrameFiltered (Record CsvHeader)
    -- processedAFrame2 = aFrame2 
    -- processedAFrame2 = aFrame2 { ffFrame = processedFrame2 }
    -- take a type-level-list of (fromName, toName, type) and use it to rename columns in suitably typed record


