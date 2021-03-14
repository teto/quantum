{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE FlexibleInstances                      #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE GADTs                      #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Types
where

-- Inspired by Frames/demo/missingData
import Frames
import Data.Monoid (First(..))
import Data.Vinyl (Rec(..), ElField(..), rapply, xrec, rmapX)
import Data.Vinyl.Functor (Compose(..), (:.))
import Data.Vinyl.Class.Method
import Net.Tcp (TcpFlag(..))
import Net.Bitset (fromBitMask, toBitMask)
import Net.IP

import Data.Word (Word8, Word16, Word32, Word64)
import Data.Text (Text)
import Frames.ShowCSV
import Frames.CSV (QuotingMode(..), ParserOptions(..))
import Frames.ColumnTypeable (Parseable(..), parseIntish, Parsed(..))
import Data.Word (Word16, Word32, Word64)
import qualified Data.Text as T
import qualified Text.Read as T
import Frames.InCore (VectorFor)
import qualified Data.Vector as V
import Numeric (readHex)
import Language.Haskell.TH
-- import GHC.TypeLits
import qualified Data.Text.Lazy.Builder as B
import Data.Typeable (Typeable)
import Control.Lens
import Control.Monad (MonadPlus, mzero)
import Frames (CommonColumns, Readable(..))
import qualified Data.Set as Set
import qualified Data.Text as TS
import Options.Applicative

-- An en passant Default class
-- class Default a where
--   def :: a

{- Describe a TCP connection, possibly an Mptcp subflow
  The equality implementation ignores several fields
-}
-- data TcpConnection = TcpConnection {
--   -- TODO use libraries to deal with that ? filter from the command line for instance ?
--   srcIp :: IP -- ^Source ip
--   , dstIp :: IP -- ^Destination ip
--   , srcPort :: Word16  -- ^ Source port
--   , dstPort :: Word16  -- ^Destination port
--   , priority :: Maybe Word8 -- ^subflow priority
--   , localId :: Word8  -- ^ Convert to AddressFamily
--   , remoteId :: Word8
--   -- TODO remove could be deduced from srcIp / dstIp ?
--   , subflowInterface :: Maybe Word32 -- ^Interface of Maybe ? why a maybe ?
--   -- add TcpMetrics member
--   -- , tcpMetrics :: Maybe [SockDiagExtension]  -- ^Metrics retrieved from kernel

-- } deriving (Show, Generic, Ord)


data TsharkFieldDesc = TsharkFieldDesc {
        fullname :: T.Text
        -- ^Test
        , colType :: Q Type
        -- ^How to reference it in plot
        , label :: Maybe T.Text
        -- ^Wether to take into account this field when creating a hash of a packet
        , hash :: Bool
    }

-- Phantom types
data Mptcp
data Tcp
-- data Protocol = Tcp | Mptcp

type TcpFlagList = [TcpFlag]

-- TODO use Word instead
newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord)
type StreamIdTcp = StreamId Tcp
type StreamIdMptcp = StreamId Mptcp

-- type MbMptcpStream = Maybe Word32
type MbMptcpStream = Maybe (StreamId Mptcp)
type MbMptcpSendKey = Maybe Word64
type MbMptcpVersion = Maybe Int
type MbMptcpExpectedToken = Maybe Word32

type MbMptcpDsn = Maybe Word64
type MbMptcpDack = Maybe Word64


-- |Filters a connection depending on its role
data ConnectionRole = RoleServer | RoleClient deriving (Show, Eq, Enum, Read, ShowCSV, Ord)


-- artificial types
declareColumn "tcpDest" ''ConnectionRole
declareColumn "mptcpDest" ''ConnectionRole

-- wireshark types
declareColumn "frameNumber" ''Word64
declareColumn "interfaceName" ''Text
declareColumn "absTime" ''Text
declareColumn "relTime" ''Double
declareColumn "ipSource" ''IP
declareColumn "ipDest" ''IP
-- TODO use tcpStream instead
declareColumn "tcpStream" ''StreamIdTcp
declareColumn "tcpSrcPort" ''Word16
declareColumn "tcpDestPort" ''Word16
declareColumn "tcpFlags" ''TcpFlagList
declareColumn "tcpOptionKinds" ''Text
declareColumn "tcpSeq" ''Word32
declareColumn "tcpLen" ''Word16
declareColumn "tcpAck" ''Word32
declareColumn "mptcpStream" ''MbMptcpStream
declareColumn "mptcpVersion" ''MbMptcpVersion
declareColumn "mptcpSendKey" ''MbMptcpSendKey
declareColumn "mptcpExpectedToken" ''MbMptcpExpectedToken
declareColumn "mptcpDsn" ''MbMptcpDsn
declareColumn "mptcpDack" ''MbMptcpDack

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
    -- Load it as a Float
    , "absTime" :-> Text
    , "relTime" :-> Double
    , "ipSource" :-> IP
    , "ipDest" :-> IP
    , "ipSrcHost" :-> Text
    , "ipDstHost" :-> Text
    -- TODO pass as a StreamIdTcp
    , "tcpStream" :-> StreamId Tcp
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

    , "mptcpExpectedToken"  :-> MbMptcpExpectedToken
    , "mptcpStream" :-> MbMptcpStream
    -- Not 
    , "mptcpSendKey" :-> Maybe Word64
    , "mptcpRecvKey" :-> Maybe Word64

    , "mptcpRecvToken" :-> MbMptcpExpectedToken
    , "mptcpDataFin" :-> Maybe Bool
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
    , "mptcpDack" :-> Maybe Word64
    , "mptcpDsn" :-> Maybe Word64
    -- , "mptcpRelatedMappings" :-> Maybe OptionList
    -- , "mptcpReinjectionOf" :-> Maybe OptionList
    -- , "mptcpReinjectedIn" :-> Maybe OptionList
    ]

-- |Can load stream ids from CSV files
readStreamId :: ReadM (StreamId a)
readStreamId = eitherReader $ \arg -> case reads arg of
  [(r, "")] -> return $ StreamId r
  _ -> Left $ "readStreamId: cannot parse value `" ++ arg ++ "`"

readConnectionRole :: ReadM ConnectionRole
readConnectionRole = eitherReader $ \arg -> case reads arg of
  [(a, "")] -> return $ a
  -- [("client", "")] -> return $ RoleClient
  _ -> Left $ "readConnectionRole: cannot parse value `" ++ arg ++ "`"


-- row / ManRow
type Packet = Record ManColumnsTshark
type PacketWithTcpDest = Record (TcpDest ': ManColumnsTshark)
type PacketWithMptcpDest = Record (MptcpDest ': MptcpDest ': ManColumnsTshark)

-- type SomeSomeFrame = Frame Packet

-- shadow param
-- @a@ be Tcp / Mptcp
-- @b@ could be the direction
-- SomeFrame Qualified
type PcapFrame a = Frame Packet
type SomeFrame = PcapFrame ()


-- TODO PcapFrame should be a monoid and a semigroup with a list of Connection []

-- Named ConnectionTcp to not clash with mptcppm's one ?
data Connection = TcpConnection {
--   -- TODO use libraries to deal with that ? filter from the command line for instance ?
  conTcpClientIp :: IP -- ^Client ip
  , conTcpServerIp :: IP -- ^Server ip
  , conTcpClientPort :: Word16  -- ^ Source port
  , conTcpServerPort :: Word16  -- ^Destination port
  , conTcpStreamId :: StreamId Tcp  -- ^ @tcp.stream@ in wireshark
  }
    | MptcpConnection {
      -- todo prefix as mpcon
      mptcpStreamId :: StreamIdMptcp
      , mptcpServerKey :: Word64
      , mptcpClientKey :: Word64
      , mptcpServerToken :: Word32
      , mptcpClientToken :: Word32
      , mptcpNegotiatedVersion :: Word8
      -- should be a subflow
      , mpconSubflows :: Set.Set MptcpSubflow

-- Ord to be able to use fromList
} deriving (Show, Eq, Ord)

data MptcpSubflow = MptcpSubflow {
      sfConn :: Connection
      , sfMptcpDest :: ConnectionRole -- ^ Destination
      , sfPriority :: Maybe Word8 -- ^subflow priority
      , sfLocalId :: Word8  -- ^ Convert to AddressFamily
      , sfRemoteId :: Word8
      --conTcp TODO remove could be deduced from srcIp / dstIp ?
      , sfInterface :: Text -- ^Interface of Maybe ? why a maybe ?
    } deriving (Show, Eq, Ord)


-- TODO rename to connection later
{- Common interface to work with TCP and MPTCP connections
-}
class StreamConnection a where
  describeConnection :: a -> Text
  -- buildFromStreamId :: a -> FrameFiltered (Record rs)
  -- list :: Connection


-- instance StreamConnection MptcpConnection where
--   describeConnection = showMptcpConnectionText


-- data SStreamId (a :: Protocol) where
--   StreamIdTcp :: SStreamId 'Tcp
--   StreamIdMptcp :: SStreamId 'Mptcp

-- | TODO adapt / rename to AFrame ? AdvancedFrames ?
-- GADT ?
data FrameFiltered rs = FrameTcp {
    ffCon :: !Connection
    -- StreamConnection b => b
    -- Frame of sthg maybe even bigger with TcpDest / MptcpDest
    , ffFrame :: Frame rs
  }
  -- | FrameSubflow {
  --   ffCon :: !MptcpSubflow
  --   , ffFrame :: Frame a

  -- }

-- -- https://stackoverflow.com/questions/52299478/pattern-match-phantom-type
-- data AFrame (p :: Protocol) where
--   AFrame :: SStreamId p -> Word32 -> AFrame p


-- |Helper to pass information across functions
data MyState = MyState {
  _stateCacheFolder :: FilePath

  , _loadedFile   :: Maybe SomeFrame  -- ^ cached loaded pcap
  , _prompt   :: String  -- ^ cached loaded pcap
}

makeLenses ''MyState



type OptionList = T.Text

    -- deriving (Read, Generic)
type FieldDescriptions = [(T.Text, TsharkFieldDesc)]

-- MUST BE KEPT IN SYNC WITH  Pcap.hs ManColumnsTshark
-- ORDER INCLUDED !
-- until we can automate this
baseFields :: FieldDescriptions
baseFields = [
    ("packetid", TsharkFieldDesc "frame.number" [t|Word64|] Nothing False)
    , ("ifname", TsharkFieldDesc "frame.interface_name" [t|Text|] Nothing False)
    , ("abstime", TsharkFieldDesc "frame.time_epoch" [t|Text|] Nothing False)
    , ("reltime", TsharkFieldDesc "frame.time_relative" [t|Text|] Nothing False)
    , ("ipsrc", TsharkFieldDesc "_ws.col.ipsrc" [t|IP|] (Just "source ip") False)
    , ("ipdst", TsharkFieldDesc "_ws.col.ipdst" [t|IP|] (Just "destination ip") False)
    , ("ipsrcHost", TsharkFieldDesc "ip.src_host" [t|Text|] (Just "source ip hostname") False)
    , ("ipdstHost", TsharkFieldDesc "ip.dst_host" [t|Text|] (Just "destination ip hostname") False)
    , ("tcpstream", TsharkFieldDesc "tcp.stream" [t|Word32|] Nothing False)
    , ("sport", TsharkFieldDesc "tcp.srcport" [t|Word16|] Nothing False)
    , ("dport", TsharkFieldDesc "tcp.dstport" [t|Word16|] Nothing False)
    , ("rwnd", TsharkFieldDesc "tcp.window_size" [t|Word32|] Nothing False)
    -- -- TODO use Word32 instead
    -- -- TODO read as a list TcpFlagList
    , ("tcpflags", TsharkFieldDesc "tcp.flags" [t|TcpFlagList|] Nothing False)
    , ("tcpoptionkind", TsharkFieldDesc "tcp.option_kind" [t|Text|] Nothing False)
    , ("tcpseq", TsharkFieldDesc "tcp.seq" [t|Word32|] (Just "Sequence number") False)
    , ("tcplen", TsharkFieldDesc "tcp.len" [t|Word32|] (Just "Acknowledgement") False)
    , ("tcpack", TsharkFieldDesc "tcp.ack" [t|Word32|] (Just "Acknowledgement") False)

    , ("tsval", TsharkFieldDesc "tcp.options.timestamp.tsval" [t|Word32|] (Just "Acknowledgement") False)
    , ("tsecr", TsharkFieldDesc "tcp.options.timestamp.tsecr" [t|Word32|] (Just "Acknowledgement") False)
    , ("expectedToken", TsharkFieldDesc "mptcp.expected_token" [t|MbMptcpExpectedToken|] (Just "Acknowledgement") False)

    , ("mptcpStream", TsharkFieldDesc "mptcp.stream" [t|MbMptcpStream|] Nothing False)
    , ("mptcpSendKey", TsharkFieldDesc "tcp.options.mptcp.sendkey" [t|Word64|] Nothing False)
    , ("mptcpRecvKey", TsharkFieldDesc "tcp.options.mptcp.recvkey" [t|Word64|] Nothing False)
    , ("mptcpRecvToken", TsharkFieldDesc "tcp.options.mptcp.recvtok" [t|Word64|] Nothing False)
    -- bool ?
    , ("mptcpDataFin", TsharkFieldDesc "tcp.options.mptcp.datafin.flag" [t|Word64|] Nothing False)
    , ("mptcpVersion", TsharkFieldDesc "tcp.options.mptcp.version" [t|Maybe Int|] Nothing False)
    , ("mptcpDack", TsharkFieldDesc "mptcp.ack" [t|Word64|] Nothing False)
    , ("mptcpDsn", TsharkFieldDesc "mptcp.dsn" [t|Word64|] Nothing False)

    ]


-- Used to parse tokens
instance (Read a, Typeable a, Frames.ColumnTypeable.Parseable a) => Frames.ColumnTypeable.Parseable (Maybe a) where
  parse txt = case T.null txt of
    True -> return $ Definitely Nothing
    False -> do
      val2 <- val
      return $ case val2 of
        Possibly x -> Possibly (Just x)
        Definitely x -> Definitely (Just x)
    where
      val :: MonadPlus m => m (Parsed a)
      val = parse txt

      -- val2 :: MonadPlus m => m (Parsed (Maybe a))
      -- val2 = Just <$> val
    -- case w64 of
    --   Left msg -> error $ "could not read " ++ show txt ++ ", error: " ++ msg
    --   Right val -> Definitely (Just val)
    -- where
    --     w64 = T.readEither (T.unpack txt)


-- TODO parse based on ,
-- instance Frames.ColumnTypeable.Parseable (Maybe OptionList) where
--   parse _ = return $ Definitely Nothing

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

instance Readable (StreamId a) where
  fromText t = case T.readMaybe (T.unpack t) of
      Just streamId -> return $ StreamId streamId
      Nothing -> mzero


instance Frames.ColumnTypeable.Parseable (StreamId Mptcp) where
  parse = parseIntish

instance Frames.ColumnTypeable.Parseable (StreamId Tcp) where
  parse = parseIntish

-- could not parse 0x00000002
-- strip leading 0x
instance Frames.ColumnTypeable.Parseable [TcpFlag] where
  parse text = case readHex (T.unpack $ T.drop 2 text) of
    -- TODO generate
    [(n, "")] -> return $ Definitely $ fromBitMask n
    _ -> error $ "TcpFlags: could not parse " ++ T.unpack text

-- TODO rewrite it as wireshark exposes it, eg, in hexa ?
instance ShowCSV [TcpFlag] where
  -- showCSV :: a -> Text
  showCSV flagList = T.concat texts
    where
      texts = map (T.pack . show .fromEnum) flagList
      res = toBitMask flagList

instance ShowCSV IP where
  showCSV = encode

instance ShowCSV Word16 where
instance ShowCSV Word32 where
instance ShowCSV Word64 where
instance ShowCSV m => ShowCSV (Maybe m) where
  showCSV = \case
    Nothing -> ""
    Just x -> showCSV x

--
instance ShowCSV (StreamId a) where
  showCSV (StreamId stream) = showCSV stream


-- type ManMaybe = Rec (Maybe :. ElField) ManColumns
-- TODO goal here is to choose the most performant Data.Vector
type instance VectorFor Word16 = V.Vector
type instance VectorFor Word32 = V.Vector
type instance VectorFor Word64 = V.Vector
type instance VectorFor (Maybe Word16) = V.Vector
type instance VectorFor (Maybe Word32) = V.Vector
type instance VectorFor (Maybe Word64) = V.Vector
type instance VectorFor IP = V.Vector
type instance VectorFor TcpFlagList = V.Vector
type instance VectorFor (StreamId a) = V.Vector

type instance VectorFor (Maybe Int) = V.Vector
type instance VectorFor (Maybe Bool) = V.Vector
type instance VectorFor (Maybe OptionList) = V.Vector
type instance VectorFor MbMptcpStream = V.Vector
type instance VectorFor ConnectionRole = V.Vector
-- type instance VectorFor MbTcpStream = V.Vector

getHeaders :: [(T.Text, TsharkFieldDesc)] -> [(T.Text, Q Type)]
getHeaders = map (\(name, x) -> (name, colType x))

headersFromFields :: [(T.Text, TsharkFieldDesc)] -> Q [(T.Text, Q Type)]
headersFromFields fields = do
  pure (getHeaders fields)


tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show

-- TODO add sthg in case it's the master subflow ?
showConnection :: Connection -> String
showConnection = TS.unpack . showConnectionText

showConnectionText :: Connection -> Text
showConnectionText con@MptcpConnection{} =
  -- showIp (srcIp con) <> ":" <> tshow (srcPort con) <> " -> " <> showIp (dstIp con) <> ":" <> tshow (dstPort con)
  tpl <> "\n" <> TS.unlines (map (showConnectionText . sfConn) (Set.toList $ mpconSubflows con))
  where
    -- showIp = Net.IP.encode
    -- tshowSubflow = tshow . showSubflow

    -- todo show server key/
    tpl :: Text
    tpl = "Server key/token: " <> tshow (mptcpServerKey con) <> "/" <> tshow ( mptcpServerToken con)
        <> "\nClient key/token: " <> tshow (mptcpClientKey con) <> "/" <> tshow ( mptcpClientToken con)
showConnectionText con@TcpConnection{} =
  showIp (conTcpClientIp con) <> ":" <> tshow (conTcpClientPort con) <> " -> "
      <> showIp (conTcpServerIp con) <> ":" <> tshow (conTcpServerPort con)
      <> "  (tcp.stream: " <> tshow (conTcpStreamId con) <> ")"
  where
    showIp = Net.IP.encode
--
-- showConnectionText con@MptcpSubflow{} = tshow (consf con)


-- showMptcpConnection :: MptcpConnection -> String
-- showMptcpConnection = TS.unpack . showMptcpConnectionText
