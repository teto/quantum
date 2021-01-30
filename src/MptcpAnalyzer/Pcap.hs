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


import Data.Monoid (First(..))
import Frames.InCore (VectorFor)
import qualified Data.Vector as V
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Tshark.TH
import Tshark.TH2
-- import Net.IP
-- creates cycle
-- import MptcpAnalyzer.Definitions
import System.IO (Handle, hGetContents)
import System.Process
import System.Exit
-- import Katip
-- import Data.Vinyl (ElField(..))
-- import Control.Lens hiding (Identity)
-- import Control.Lens.TH
import Frames.TH
import Frames
import Frames.ShowCSV
import Frames.CSV (produceTextLines, pipeTableEitherOpt, readFileLatin1Ln, readTableMaybeOpt, QuotingMode(..), ParserOptions(..))
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
import Data.Word (Word8, Word16, Word32, Word64)
import Net.Tcp
-- import Net.Tcp.Constants
import Numeric (readHex)
import Net.Tcp ( TcpFlag(..), numberToTcpFlags)
import MptcpAnalyzer.Types
import qualified Pipes.Prelude as P
import Pipes (cat, Producer, (>->))
import Data.Vinyl (Rec(..), ElField(..), rapply, xrec, rmapX)
import Data.Vinyl.Functor (Compose(..), (:.))
import Data.Vinyl.Class.Method

-- Phantom types
data Mptcp
data Tcp

-- TODO use Word instead
newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord)

-- tableTypes is a Template Haskell function, which means that it is executed at compile time. It generates a data type for our CSV, so we have everything under control with our types.


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




type MbMptcpStream = Maybe Word32
type MbVersion = Maybe Int

declareColumn "frameNumber" ''Word64
declareColumn "interfaceName" ''Text
declareColumn "frameEpoch" ''Text
declareColumn "ipSource" ''IP
declareColumn "ipDest" ''IP
-- TODO use tcpStream instead
declareColumn "tcpStream" ''Word32
declareColumn "tcpSrcPort" ''Word16
declareColumn "tcpDestPort" ''Word16
declareColumn "tcpFlags" ''TcpFlagList
declareColumn "tcpOptionKinds" ''Text
declareColumn "tcpSeq" ''Word32
declareColumn "tcpLen" ''Word16
declareColumn "tcpAck" ''Word32
declareColumn "mptcpStream" ''MbMptcpStream
declareColumn "mptcpVersion" ''MbVersion

-- tableTypesExplicitFull myRow
--   rowGen { rowTypeName = "Packet"
--         , separator = "|"
--         -- TODO I could generate it as well
--         -- , columnNames
--     })

-- headersFromFields
-- headersFromFields baseFields
-- $(headersFromFields baseFields)
-- tableTypesExplicitFull [] myRow
-- tableTypesExplicitFull myHeaders myRow

-- myRowGen "ManColumnsTshark" baseFields
-- type OptionList = [Int]

-- ManColumnsTshark :: [(Symbol, *)]
type ManColumnsTshark = '[
    "packetId" :-> Word64
    , "interfaceName" :-> Text
    , "relTime" :-> Text
    , "absTime" :-> Text
    , "ipSource" :-> IP
    , "ipDest" :-> IP
    , "ipSrcHost" :-> Text
    , "ipDstHost" :-> Text
    , "tcpStream" :-> Word32
    , "tcpSrcPort" :-> Word16
    , "tcpDestPort" :-> Word16
    , "rwnd" :-> Word32
    , "tcpFlags" :-> TcpFlagList
    , "tcpOptionKinds" :-> Text
    , "tcpSeq"  :-> Word32
    , "tcpLen"  :-> Word16
    , "tcpAck"  :-> Word32

    -- -- timetsamp Val
    , "tsVal"  :-> Maybe Word32
    -- -- timestamp echo-reply
    , "tsEcr"  :-> Maybe Word32

    , "expectedToken"  :-> Maybe Word32
    , "mptcpStream" :-> Maybe Word32
    , "mptcpSendKey" :-> Maybe Word64
    , "mptcpRecvKey" :-> Maybe Word64

    , "mptcpRecvToken" :-> Maybe Word32
    , "mptcpdataFin" :-> Maybe Bool
    -- mptcp version for now is 0 or 1
    -- maybe use a word9 instead
    , "mptcpVersion" :-> Maybe Int
    -- TODO check
    -- , "tcpOptionSubtypes" :-> OptionList
    -- , "mptcpRawDsn" :-> Word64
    -- , "mptcpRawDack" :-> Word64
    -- , "mptcpSSN" :-> Word64
    -- , "mptcpDssLen" :-> Word32
    -- , "mptcpAddrId" :-> Maybe Int
    -- , "mptcpRawDsn" :-> Word64
    -- relative or abs
    -- , "mptcpDack" :-> Word64
    -- , "mptcpDsn" :-> Word64
    -- , "mptcpRelatedMappings" :-> OptionList
    -- , "mptcpReinjectionOf" :-> Maybe OptionList
    -- , "mptcpReinjectedIn" :-> Maybe OptionList
    ]


-- row / ManRow
type Packet = Record ManColumnsTshark

type PcapFrame = Frame Packet

-- shadow type to know if it was filtered or not
-- Make it a record ?
type ConFrame a = PcapFrame
-- type PcapFrame = Frame ManColumnsTshark


data TsharkParams = TsharkParams {
      tsharkBinary :: String,
      tsharkOptions :: [(String, String)],
      csvDelimiter :: Char,
      tsharkReadFilter :: Maybe String
    }

defaultParserOptions :: ParserOptions
defaultParserOptions = ParserOptions Nothing (T.pack [csvDelimiter defaultTsharkPrefs]) NoQuoting

-- -- nub => remove duplicates
-- or just get the column
-- L.fold
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
  -- readTableOpt defaultParserOptions path
  -- holesFilled path
  -- loadRowsEither path
  eitherProcessed path
  )

-- maybeRows :: MonadSafe m => Producer (Rec (Maybe :. ElField) (RecordColumns Row)) m ()
-- maybeRows = readTableMaybe "test/data/prestigePartial.csv"
loadMaybeRows :: MonadSafe m => FilePath -> Producer (Rec (Maybe :. ElField) (RecordColumns Packet)) m ()
loadMaybeRows path = 
  -- inCoreAoS (
  readTableMaybeOpt defaultParserOptions path
  -- )

-- | Produce the lines of a latin1 (or ISO8859 Part 1) encoded file as
-- ’T.Text’ values.
-- readFileLatin1Ln :: P.MonadSafe m => FilePath -> P.Producer [T.Text] m ()
-- readFileLatin1Ln fp = pipeLines (try . fmap T.decodeLatin1 . B8.hGetLine) fp
--                       >-> P.map (tokenizeRow defaultParser)

type ManEither = Rec (Either T.Text :. ElField) (RecordColumns Packet)

-- -> P.Pipe T.Text (Rec (Either T.Text :. ElField) rs) m ()
  -- T.readFile path
  -- readFileLatin1Ln
  -- produceTokens

-- pipteTable will tokenize on its own
loadRowsEither :: MonadSafe m => FilePath -> Producer ManEither m ()
loadRowsEither path =  produceTextLines path >-> pipeTableEitherOpt defaultParserOptions

-- loadRowsEitherFiltered :: MonadSafe m => FilePath -> Producer ManEither m ()
-- >-> P.map (tokenizeRow defaultParser)

eitherProcessed :: MonadSafe m => FilePath -> Producer Packet m ()
eitherProcessed path = loadRowsEither path  >-> P.map fromEither
  where
        -- holeFiller :: Rec (Either Text :. ElField) (RecordColumns Packet) -> Maybe Packet
        -- holeFiller = recMaybe . rmapX @(First :. ElField) getFirst
        --            -- . rapply (rmapX @(First :. ElField) (flip mappend) def)
        --            . rmapX @_ @(First :. ElField) First
        --Rec (ElfField) (RecordColumns Packet)

        fromEither :: Rec (Either Text :. ElField) (RecordColumns Packet) -> Packet
        fromEither x = case recEither x of
          Left _txt -> error ( "eitherProcessed failure : " ++ T.unpack _txt ++ "toto")
          Right pkt -> pkt

-- | Undistribute 'Maybe' from a 'Rec' 'Maybe'. This is just a
-- specific usage of 'rtraverse', but it is quite common.
recEither :: Rec (Either Text :. ElField) cs -> Either Text (Record cs)
recEither = rtraverse getCompose

-- | Undistribute 'Maybe' from a 'Rec' 'Maybe'. This is just a
-- specific usage of 'rtraverse', but it is quite common.
-- recMaybe :: Rec (Maybe :. ElField) cs -> Maybe (Record cs)
-- recMaybe = rtraverse getCompose

-- readFileLatin1Ln :: P.MonadSafe m => FilePath -> P.Producer [T.Text] m ()
-- readFileLatin1Ln fp = pipeLines (try . fmap T.decodeLatin1 . B8.hGetLine) fp
--                       >-> P.map (tokenizeRow defaultParser)

-- | Fill in missing columns with a default 'Row' value synthesized
-- from 'Default' instances.
holesFilled :: MonadSafe m => FilePath -> Producer Packet m ()
holesFilled path = readTableMaybeOpt defaultParserOptions  path  >-> P.map (fromJust . holeFiller)
  where holeFiller :: Rec (Maybe :. ElField) (RecordColumns Packet) -> Maybe Packet
        holeFiller = recMaybe . rmapX @(First :. ElField) getFirst
                   -- . rapply (rmapX @(First :. ElField) (flip mappend) def)
                   . rmapX @_ @(First :. ElField) First
        fromJust = maybe (error "Frames holesFilled failure") id

-- showFilledHoles :: IO ()
-- showFilledHoles = runSafeT (pipePreview holesFilled 10 cat)

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

