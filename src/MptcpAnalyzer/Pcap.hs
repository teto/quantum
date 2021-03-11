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
{-# LANGUAGE ConstraintKinds,
             DataKinds,
             EmptyCase,
             FlexibleContexts,
             FlexibleInstances,
             FunctionalDependencies,
             KindSignatures,
             GADTs,
             MultiParamTypeClasses,
             PatternSynonyms,
             PolyKinds,
             ScopedTypeVariables,
             TypeFamilies,
             TypeOperators,
             UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Pcap
-- (SomeFrame, TsharkParams(..),
--     defaultTsharkPrefs
--     , defaultTsharkOptions
--     , generateCsvCommand
--     , exportToCsv
--     , loadRows
--     , getTcpStreams
--     )
where


import Tshark.TH
import Tshark.TH2

import Data.Monoid (First(..))
import qualified Data.Vector as V
import qualified Data.Text as T
import qualified Data.Text.IO as T
import System.IO (BufferMode(LineBuffering), hSetBuffering, SeekMode(AbsoluteSeek), hSeek, Handle, hGetContents)
import System.Process
import System.Exit
import Frames.TH
import Frames
-- import Frames.InCore
import Frames.ShowCSV
import Frames.Col
import Frames.CSV (produceTextLines, pipeTableEitherOpt, readFileLatin1Ln, readTableMaybeOpt, QuotingMode(..), ParserOptions(..))
import Frames.ColumnTypeable (Parseable(..), parseIntish, Parsed(..))
-- for Record
-- import Frames.Rec (Record(..))
import Net.IP
import Data.List (intercalate)
-- for symbol
-- import GHC.Types
import qualified Data.Set as Set
import qualified Control.Foldl as L
-- import Language.Haskell.TH
-- import Language.Haskell.TH.Syntax
-- import Lens.Micro
-- import Lens.Micro.Extras
import Control.Lens
import Data.Word (Word8, Word16, Word32, Word64)
import Numeric (readHex)
import Net.Tcp ( TcpFlag(..))
import MptcpAnalyzer.Types
import qualified Pipes.Prelude as P
import Pipes (cat, Producer, (>->))
import Data.Vinyl (Rec(..), ElField(..), rapply, xrec, rmapX)
import Data.Vinyl.Functor (Compose(..), (:.))
import Data.Vinyl.Class.Method
import Data.Maybe (fromJust, catMaybes)
import GHC.Base (Symbol)
import GHC.TypeLits (KnownSymbol)
import GHC.List (foldl')
import qualified Frames.InCore


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





-- shadow type to know if it was filtered or not
-- Make it a record ?
type ConFrame a = SomeFrame
-- type SomeFrame = Frame ManColumnsTshark


data TsharkParams = TsharkParams {
      tsharkBinary :: String,
      tsharkOptions :: [(String, String)],
      csvDelimiter :: Char,
      tsharkReadFilter :: Maybe String
    }

-- first argument allows to override csv header ("headerOverride")
defaultParserOptions :: ParserOptions
defaultParserOptions = ParserOptions Nothing (T.pack [csvDelimiter defaultTsharkPrefs]) NoQuoting

-- nub => remove duplicates
-- or just get the column
getTcpStreams :: SomeFrame -> [StreamIdTcp]
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
{- Export to CSV

-}
exportToCsv :: TsharkParams ->
               FilePath  -- ^Path to the pcap
               -> FilePath -- ^ temporary file
               -> Handle -- ^ temporary file
              -- ^See haskell:readCreateProcessWithExitCode
                -> IO (FilePath, ExitCode, String)
exportToCsv params pcapPath path tmpFileHandle = do
    let
        (RawCommand bin args) = generateCsvCommand fields pcapPath params
        createProc :: CreateProcess
        createProc = (proc bin args) {
            std_err = CreatePipe,
            std_out = UseHandle tmpFileHandle
            }
    putStrLn $ "Exporting fields " ++ show fields
    putStrLn $ "Command run: " ++ show (RawCommand bin args)
    -- TODO write header
    -- withCreateProcess (proc cmd args) { ... }  $ \stdin stdout stderr ph -> do
    -- runInteractiveProcess
    -- TODO redirect stdout towards the out handle
    hSetBuffering tmpFileHandle LineBuffering
    hSeek tmpFileHandle AbsoluteSeek 0 >> T.hPutStrLn tmpFileHandle fieldHeader 
    (_, _, Just herr, ph) <-  createProcess_ "error" createProc
    exitCode <- waitForProcess ph
    -- TODO do it only in case of error ?
    err <- hGetContents herr
    return (path, exitCode, err)
    where
      fields :: [T.Text]
      fields = map (\(_, desc) -> fullname desc) baseFields

      csvSeparator = T.pack [csvDelimiter params]
      fieldHeader :: Text
      fieldHeader = T.intercalate csvSeparator (map (\(name, _) -> name) baseFields)

-- "data/server_2_filtered.pcapng.csv"
-- la le probleme c'est que je ne passe pas d'options sur les separators etc
-- ca foire silencieusement ??
-- maybe use a readTableMaybe instead
-- readTable path

loadRows :: FilePath -> IO SomeFrame
loadRows path = inCoreAoS (
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

{- |Load rows and errors when it can't load a specific line
-}
eitherProcessed :: MonadSafe m => FilePath -> Producer Packet m ()
eitherProcessed path = loadRowsEither path  >-> P.map fromEither
  where
    fromEither :: Rec (Either Text :. ElField) (RecordColumns Packet) -> Packet
    fromEither x = case recEither x of
      Left _txt -> error ( "eitherProcessed failure : " ++ T.unpack _txt)
      Right pkt -> pkt

-- | Undistribute 'Maybe' from a 'Rec' 'Maybe'. This is just a
-- specific usage of 'rtraverse', but it is quite common.
recEither :: Rec (Either Text :. ElField) cs -> Either Text (Record cs)
recEither = rtraverse getCompose

-- | Undistribute 'Maybe' from a 'Rec' 'Maybe'. This is just a
-- specific usage of 'rtraverse', but it is quite common.
-- recMaybe :: Rec (Maybe :. ElField) cs -> Maybe (Record cs)
-- recMaybe = rtraverse getCompose

-- http://acowley.github.io/Frames/#orgf328b25

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

-- buildAFrameFromConnection :: Frame -> StreamId a -> SomeFrame
-- buildAFrameFromConnection streamId@StreamIdTcp = getTcp

-- @(StreamId Tcp)
-- return AFrame a
buildAFrameFromStreamId :: SomeFrame -> StreamId a -> SomeFrame
buildAFrameFromStreamId frame (SStreamId 'Tcp)streamId = getTcpFrame frame streamId

{- 
-}
getTcpFrame :: SomeFrame -> StreamId Tcp -> Either String FrameFiltered
getTcpFrame = buildConnectionFromTcpStreamId

-- | For now assume the packet is the first syn from client to server
buildTcpConnectionFromRow :: Packet -> Connection
buildTcpConnectionFromRow r =
  TcpConnection {
    conTcpClientIp = r ^. ipSource
    , conTcpServerIp = r ^. ipDest
    , conTcpClientPort = r ^. tcpSrcPort
    , conTcpServerPort = r ^. tcpDestPort
    , conTcpStreamId = r ^. tcpStream
    -- , priority = Nothing  -- for now
    -- , localId = 0
    -- , remoteId = 0
    -- , subflowInterface = Nothing
  }

{- Builds a Tcp connection from a non filtered frame
-}
buildConnectionFromTcpStreamId :: SomeFrame -> StreamId Tcp -> Either String FrameFiltered
buildConnectionFromTcpStreamId frame streamId =
    -- Right $ frameLength synPackets
    if frameLength synPackets < 1 then
      Left $ "No packet with any SYN flag for tcpstream " ++ show streamId
    else
      -- TODO check who is client
      Right $ FrameTcp (buildTcpConnectionFromRow $ frameRow synPackets 0) streamPackets
    where
      streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId) frame
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets


-- | Sets mptcp role column
-- TODO maybe je devrais juste generer un 
addMptcpDest :: (
      Frames.InCore.RecVec rs,
      MptcpStream ∈ rs, TcpStream  ∈ rs, IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs) =>
      Frame (Record rs)
      -> Connection
      -> Frame (Record  ( MptcpDest ': TcpDest ': rs ))
addMptcpDest frame con@MptcpConnection{} =
    -- foldl' (\tframe sf -> addDestToFrame tframe sf) startingFrame subflows
    -- map subflows (addTcpDestToFrame frame)
    mconcat subflowFrames
    where
      filteredFrame = filterFrame  (\x -> x ^. mptcpStream == Just (mptcpStreamId con)) frame

      subflowFrames = map addDestsToSubflowFrames subflows

      addDestsToSubflowFrames sf = addMptcpDestToFrame (addTcpDestToFrame frame sf) sf

      -- frameWithTcpDest = foldl' (\tframe sf -> addTcpDestToFrame tframe sf) frame subflows
      -- addDestToFrame = 

      addMptcpDest' role x = (Col $ role) :& x

      addMptcpDestToFrame frame' sf = fmap (addMptcpDest' (consfMptcpDest sf)) frame'

      -- startingFrame = fmap (addMptcpDest' (consfMptcpDest sf)) frameWithTcpDest
      startingFrame = fmap setTempDests frame
      setTempDests :: Record rs2 -> Record ( MptcpDest ': TcpDest ': rs2)
      setTempDests x = (Col RoleClient) :& (Col RoleClient) :& x
      addMptcpDestToRec x role = (Col $ role) :& x
      subflows = []
addMptcpDest frame _ = error "should not happen"


-- | Sets TCP role column
-- append a column with a value role
-- Todo accept a 'FrameFiltered'
-- (Frames.InCore.)
addTcpDestToFrame ::   (Frames.InCore.RecVec rs, TcpStream ∈ rs, IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs)
    => Frame (Record rs) -> Connection -> Frame (Record  ( TcpDest ': rs ))
addTcpDestToFrame frame con = fmap (\x -> addTcpDestToRec x (computeTcpDest x con)) streamFrame
    where
      streamFrame = filterFrame  (\x -> x ^. tcpStream == conTcpStreamId con) frame

computeTcpDest :: (TcpStream ∈ rs, IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs) => Record rs -> Connection -> ConnectionRole
computeTcpDest x con  = if (rgetField @IpSource x) == (conTcpClientIp con)
                && (rgetField @IpDest x) == (conTcpServerIp con)
                && (rgetField @TcpSrcPort x) == (conTcpClientPort con)
                && (rgetField @TcpDestPort x) == (conTcpServerPort con)
                && (rgetField @TcpDestPort x) == (conTcpServerPort con)
                -- TODO should error if not the same streamId
                -- && (rgetField @TcpStream x) == (conTcpStreamId con)
        then RoleClient else RoleServer

-- append a field with a value role
addTcpDestToRec :: (TcpStream ∈ rs, IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs) => Record rs -> ConnectionRole ->  Record  ( TcpDest ': rs )
addTcpDestToRec x role = (Col $ role) :& x


buildSubflow :: SomeFrame -> StreamId Tcp -> Connection
buildSubflow frame (StreamId sfId) = case buildConnectionFromTcpStreamId frame (StreamId sfId) of
  Right con@FrameTcp{} -> ffTcpCon con
  _ -> error "should not happen"

buildMptcpConnectionFromStreamId :: SomeFrame -> StreamId Mptcp -> Either String Connection
buildMptcpConnectionFromStreamId frame streamId = do
    -- Right $ frameLength synPackets
    if frameLength streamPackets < 1 then
      Left $ "No packet with mptcp.stream == " ++ show streamId
    else if frameLength synAckPackets < 1 then
      Left $ "No syn/ack packet found for stream" ++ show streamId ++ " First packet: "
      -- ++ show streamPackets
    else
      -- TODO now add a check on abstime
      -- if ds.loc[server_id, "abstime"] < ds.loc[client_id, "abstime"]:
      --     log.error("Clocks are not synchronized correctly")
      Right $ MptcpConnection {
        mptcpStreamId = streamId
        , mptcpServerKey = fromJust $ synAckPacket ^. mptcpSendKey
        , mptcpClientKey = fromJust $ synPacket ^. mptcpSendKey
        , mptcpServerToken = fromJust $ synAckPacket ^. mptcpExpectedToken
        , mptcpClientToken = fromJust $ synPacket ^. mptcpExpectedToken
        , mptcpNegotiatedVersion = fromIntegral $ fromJust clientMptcpVersion :: Word8

        , mpconSubflows = Set.fromList subflows
        -- , localIds = Set.empty
        -- , remoteIds = Set.empty
      }
      --  $ frameRow synPackets 0
    where
      streamPackets :: SomeFrame
      streamPackets = filterFrame  (\x -> x ^. mptcpStream == Just streamId) frame
      -- suppose tcpflags is a list of flags, check if it is in the list
      -- of type FrameRec [(Symbol, *)]
      -- Looking for synack packets
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
      synAckPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags) && TcpFlagAck `elem` (x ^. tcpFlags)) streamPackets

      synPacket = frameRow synPackets 0
      synAckPacket = frameRow synAckPackets 0

      masterTcpstreamId = synPacket ^. tcpStream

      clientMptcpVersion = synPacket ^. mptcpVersion

      subflows = map (buildSubflow frame) (getTcpStreams streamPackets)
