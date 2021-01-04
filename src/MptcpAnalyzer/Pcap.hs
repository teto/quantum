{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE FlexibleInstances                      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE FlexibleContexts, QuasiQuotes #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Pcap
-- (PcapFrame, TsharkParams(..),
--     defaultTsharkPrefs
--     , defaultTsharkOptions
--     , generateCsvCommand
--     , exportToCsv
--     , loadRows
--     , getTcpStreams
--     )
where

import Frames.InCore (VectorFor)
import qualified Data.Vector as V
-- import Frames.InCore (VectorFor)
import qualified Data.Text as T
import Tshark.TH
-- import Net.IP
import System.IO (Handle, hGetContents)
import System.Process
import System.Exit
-- import Katip
-- import Data.Vinyl (ElField(..))
-- import Control.Lens hiding (Identity)
-- import Control.Lens.TH
import Frames.TH
import Frames
import Frames.CSV (QuotingMode(..), ParserOptions(..))
import Frames.ColumnTypeable (Parseable(..), parseIntish, Parsed(..))
-- for Record
-- import Frames.Rec (Record(..))
import Net.IP
import Data.List (intercalate)
-- for symbol
-- import GHC.Types
import qualified Control.Foldl as L
-- import Language.Haskell.TH
-- import Language.Haskell.TH.Syntax
-- import Lens.Micro
-- import Lens.Micro.Extras
import Control.Lens
-- import qualified Data.Vector as V
import Data.Word (Word16, Word32, Word64)
import Net.Tcp
-- import Net.Tcp.Constants
import Numeric (readHex)

-- instance Parseable TsharkField where
--   representableAsType
-- parse :: MonadPlus m => Text -> m (Parsed a) 
    -- parse text = return $ Definitely

-- tableTypes is a Template Haskell function, which means that it is executed at compile time. It generates a data type for our CSV, so we have everything under control with our types.
-- tableTypes "Packet" "data/server_2_filtered.pcapng.csv"
-- type PcapFrame = Frame Packet
-- tableTypes "Packet" "data/test-simple.csv"


-- on veut la generer
-- [[t|Ident Int|], [t|Happiness|]]
-- tableTypesExplicit' :: [Q Type] -> RowGen a -> FilePath -> DecsQ
-- tableTypesExplicit'

-- tableTypesExplicit'
--   (getTypes baseFields)
--   -- [ Field Word64 ]
--   -- [[t| Word64|]]
--   ((rowGen "data/test-1col.csv")
--   { rowTypeName = "Packet"
--         , separator = ","
--         -- TODO I could generate it as well
--         -- , columnNames
--     })
--     -- path
--     "data/test-simple.csv"

instance Frames.ColumnTypeable.Parseable Word16 where
  parse = parseIntish
instance Frames.ColumnTypeable.Parseable Word32 where
  parse = parseIntish
instance Frames.ColumnTypeable.Parseable Word64 where
  parse = parseIntish

instance Frames.ColumnTypeable.Parseable IP where
  -- parse :: MonadPlus m => T.Text -> m (Parsed a)
-- IP.decode :: Text -> Maybe IP
  -- fmap Definitely
  parse text = case decode text of
    Nothing -> return $ Possibly $ ipv4 0 0 0 0
    Just ip -> return $ Definitely ip



-- instance Frames.ColumnTypeable.Parseable Word64 where
--   parse = parseIntish



-- could not parse 0x00000002
-- strip leading 0x
instance Frames.ColumnTypeable.Parseable [TcpFlag] where
  parse text = case readHex (T.unpack $ T.drop 2 text) of
    -- TODO generate
    [(n, "")] -> return $ Definitely $ numberToTcpFlags n
    _ -> error $ "could not parse " ++ T.unpack text

-- tcpFlags as a list of flags

type TcpFlagList = [TcpFlag]

declareColumn "frameNumber" ''Word64
declareColumn "interfaceName" ''Text
declareColumn "frameEpoch" ''IP
declareColumn "ipSource" ''IP
declareColumn "ipDest" ''IP
declareColumn "tcpStream" '' Word32
declareColumn "mptcpStream" '' Word32
declareColumn "tcpSrcPort" ''Word16
declareColumn "tcpDestPort" ''Word16
-- declareColumn "tcpFlags" ''Text
declareColumn "tcpFlags" ''TcpFlagList
declareColumn "tcpOptionKinds" ''Text
declareColumn "tcpSeq" ''Word32
declareColumn "tcpLen" ''Word16
declareColumn "tcpAck" ''Word32

-- TODO need to declare an explicit record type ?
recDecExplicit

type ManColumns = '["frame.number" :-> Word64
                    , "frame.interface_name" :-> String
                    -- TODO make it as a timestamp, Word64 for instance
                    , "frame.time_epoch" :-> String
                    , "_ws.col.ipsrc" :-> IP
                    , "_ws.col.ipdst" :-> IP
                    , "tcp.stream" :-> Word32
                    , "tcp.flags" :-> String
                    , "mptcp.stream" :-> Word32
                    , "tcp.srcport" :-> Word16
                    , "tcp.dstport" :-> Word16
                    ]

-- type ManRowPacket = Record ManColumns
type ManRowPacket = Record '[
    FrameNumber
    , InterfaceName
    , FrameEpoch
    , IpSource, IpDest
    , TcpStream
    , TcpSrcPort, TcpDestPort
    , TcpFlags
    , TcpOptionKinds
    , TcpSeq
    , TcpLen
    , TcpAck
    -- , MptcpStream
    ]

type Packet = ManColumns

-- type ManMaybe = Rec (Maybe :. ElField) ManColumns
-- TODO goal here is to choose the most performant Data.Vector
type instance VectorFor Word16 = V.Vector
type instance VectorFor Word32 = V.Vector
type instance VectorFor Word64 = V.Vector
type instance VectorFor IP = V.Vector
type instance VectorFor TcpFlagList = V.Vector

-- type PcapFrame = Frame Packet
type PcapFrame = Frame ManRowPacket


data TsharkParams = TsharkParams {
      tsharkBinary :: String,
      tsharkOptions :: [(String, String)],
      csvDelimiter :: Char,
      tsharkReadFilter :: Maybe String
    }

defaultParserOptions :: ParserOptions
defaultParserOptions = ParserOptions Nothing (T.pack [csvDelimiter defaultTsharkPrefs]) NoQuoting

-- nub => remove duplicates
getTcpStreams :: PcapFrame -> [Word32]
getTcpStreams ps =
    L.fold L.nub (view tcpStream <$> ps)


-- |Generate the tshark command to export a pcap into a csv
generateCsvCommand :: [T.Text] -- ^Fields to exports e.g., "mptcp.stream"
          -> FilePath    -- ^ path towards the pcap file
          -> TsharkParams
          -> CmdSpec
generateCsvCommand fieldNames pcapFilename tsharkParams =
    RawCommand (tsharkBinary tsharkParams) args
    where
    -- for some reasons, -Y does not work so I use -2 -R instead
    -- quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
    -- single-quotes, n no quotes (the default).
    -- the -2 is important, else some mptcp parameters are not exported
        start = [
              "-r", pcapFilename,
              "-E", "separator=" ++ [csvDelimiter tsharkParams]
            ]
        -- if self.profile:
        --     cmd.extend(['-C', self.profile])
        args :: [String]
        args = (start ++ opts ++ readFilter ) ++ map T.unpack  fields

        opts :: [String]
        opts = foldr (\(opt, val) l -> l ++ ["-o", opt ++ ":" ++ val]) [] (tsharkOptions tsharkParams)

        readFilter :: [String]
        readFilter = case tsharkReadFilter tsharkParams of
            Just x ->["-2", "-R", x]
            Nothing -> []

        fields :: [T.Text]
        fields = ["-T", "fields"]
            ++ Prelude.foldr (\fieldName l -> ["-e", fieldName] ++ l) [] fieldNames

-- TODO pass a list of options too
-- TODO need to override 'WIRESHARK_CONFIG_DIR' = tempfile.gettempdir()
-- (MonadIO m, KatipContext m) =>
exportToCsv ::  TsharkParams ->
                FilePath  -- ^Path to the pcap
                -> FilePath -> Handle -- ^ temporary file
              -- ^See haskell:readCreateProcessWithExitCode
                -> IO (FilePath, ExitCode, String)
exportToCsv params pcapPath path fd = do
    let
        (RawCommand bin args) = generateCsvCommand fields pcapPath params
        createProc :: CreateProcess
        createProc = (proc bin args) {
            std_err = CreatePipe,
            std_out = UseHandle fd
            }
    putStrLn $ "Exporting fields " ++ show fields
    putStrLn $ "Command run: " ++ show (RawCommand bin args)
    -- TODO write header
    -- withCreateProcess (proc cmd args) { ... }  $ \stdin stdout stderr ph -> do
    -- runInteractiveProcess
    -- TODO redirect stdout towards the out handle
    -- TODO use createProcess instead
    -- readCreateProcessWithExitCode ignores std_out/std_err
    -- IO (Maybe Handle, Maybe Handle, Maybe Handle, ProcessHandle)
    (_, _, Just herr, ph) <-  createProcess_ "error" createProc
    exitCode <- waitForProcess ph
    -- TODO do it only in case of error ?
    err <- hGetContents herr
    -- TODO retrun stderr
    return (path, exitCode, err)
    where
      fields :: [T.Text]
      fields = map (\(_, desc) -> fullname desc) baseFields

-- "data/server_2_filtered.pcapng.csv"
-- la le probleme c'est que je ne passe pas d'options sur les separators etc
-- ca foire silencieusement ??
-- maybe use a readTableMaybe instead
-- readTable path

loadRows :: FilePath -> IO PcapFrame
loadRows path = inCoreAoS (
  readTableOpt defaultParserOptions path
  )

-- http://acowley.github.io/Frames/#orgf328b25
-- movieStream :: MonadSafe m => Producer User m ()
-- movieStream = readTableOpt userParser "data/ml-100k/u.user"

-- todo pass as text ?
-- derive from Order ?
defaultTsharkOptions :: [(String, String)]
defaultTsharkOptions = [
      -- TODO join these
      ("gui.column.format", intercalate "," [ "Time","%At","ipsrc","%s","ipdst","%d"]),
      -- "tcp.relative_sequence_numbers": True if tcp_relative_seq else False,
      ("tcp.analyze_sequence_numbers", "true"),
      ("mptcp.analyze_mappings", "true"),
      ("mptcp.relative_sequence_numbers", "true"),
      ("mptcp.intersubflows_retransmission", "true"),
      -- # Disable DSS checks which consume quite a lot
      ("mptcp.analyze_mptcp", "true")
      ]

-- data TsharkPrefs = TsharkPrefs {
--     analyzeTcpSeq :: Bool
--     , analyzeMptcp :: Bool
--     , mptcpRelSeq :: Bool
--     , analyzeMptcp :: Bool
--   } deriving Show

defaultTsharkPrefs :: TsharkParams
defaultTsharkPrefs = TsharkParams {
      tsharkBinary = "tshark",
      tsharkOptions = defaultTsharkOptions,
      csvDelimiter = '|',
      tsharkReadFilter = Just "mptcp or tcp and not icmp"
    }

