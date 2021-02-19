{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances                      #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Types
where

-- Inspired by Frames/demo/missingData
import Data.Monoid (First(..))
import Data.Vinyl (Rec(..), ElField(..), rapply, xrec, rmapX)
import Data.Vinyl.Functor (Compose(..), (:.))
import Data.Vinyl.Class.Method

import Net.IP
import Data.Text (Text)
-- import Frames.TH
-- import Frames
import Frames.ShowCSV
import Frames.CSV (QuotingMode(..), ParserOptions(..))
import Frames.ColumnTypeable (Parseable(..), parseIntish, Parsed(..))
import Data.Word (Word16, Word32, Word64)
import qualified Data.Text as T
import qualified Text.Read as T
import Net.Tcp ( TcpFlag(..), numberToTcpFlags)
import Frames.InCore (VectorFor)
import qualified Data.Vector as V
import Numeric (readHex)
import Language.Haskell.TH
-- import GHC.TypeLits
import qualified Data.Text.Lazy.Builder as B
import Data.Typeable (Typeable)

import Control.Monad (MonadPlus, mzero)
import Frames (CommonColumns, Readable(..))

-- An en passant Default class
-- class Default a where
--   def :: a

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

-- TODO use Word instead
newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord)
type StreamIdTcp = StreamId Tcp
type StreamIdMptcp = StreamId Mptcp

-- type MbMptcpStream = Maybe Word32
type MbMptcpStream = Maybe (StreamId Mptcp)
type MbMptcpSendKey = Maybe Word64
type MbMptcpVersion = Maybe Int
type MbMptcpExpectedToken = Maybe Word32

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


-- parseIntish t =
--   Definitely <$> fromText (fromMaybe t (T.stripSuffix (T.pack ".0") t))

-- customWordParser :: Read a => T.Text -> Parsed (Maybe a)
-- customWordParser txt = case T.null txt of
--     True -> Definitely Nothing
--     False -> Definitely $ Just w64
--     where
--         w64 = read (T.unpack txt) :: a


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

instance Readable (StreamId Mptcp) where
  --
  fromText t = case T.readMaybe (T.unpack t) of
      Just streamId -> return $ StreamId streamId
      Nothing -> mzero


-- forall a.
instance Frames.ColumnTypeable.Parseable (StreamId Mptcp) where
  parse = parseIntish


-- could not parse 0x00000002
-- strip leading 0x
instance Frames.ColumnTypeable.Parseable [TcpFlag] where
  parse text = case readHex (T.unpack $ T.drop 2 text) of
    -- TODO generate
    [(n, "")] -> return $ Definitely $ numberToTcpFlags n
    _ -> error $ "TcpFlags: could not parse " ++ T.unpack text

-- tcpFlags as a list of flags

type TcpFlagList = [TcpFlag]

instance ShowCSV [TcpFlag] where
  -- showCSV :: a -> Text
  -- default showCSV :: Show a => a -> Text
  -- showCSV = T.pack . show
  showCSV flagList = T.concat texts
    where
      texts = map (T.pack . show .fromEnum) flagList

instance ShowCSV IP where
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

type instance VectorFor (Maybe Int) = V.Vector
type instance VectorFor (Maybe Bool) = V.Vector
type instance VectorFor (Maybe OptionList) = V.Vector
type instance VectorFor MbMptcpStream = V.Vector
-- type instance VectorFor MbTcpStream = V.Vector

getHeaders :: [(T.Text, TsharkFieldDesc)] -> [(T.Text, Q Type)]
getHeaders = map (\(name, x) -> (name, colType x))

headersFromFields :: [(T.Text, TsharkFieldDesc)] -> Q [(T.Text, Q Type)]
headersFromFields fields = do
  pure (getHeaders fields)
