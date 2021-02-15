{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances                      #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Types
where

-- Inspired by Frames/demo/missingData
import Data.Monoid (First(..))
import Data.Vinyl (Rec(..), ElField(..), rapply, xrec, rmapX)
import Data.Vinyl.Functor (Compose(..), (:.))
import Data.Vinyl.Class.Method

import Net.IP
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

-- type MbMptcpStream = Maybe Word32
type MbMptcpStream = Maybe (StreamId Mptcp)
type MbMptcpSendKey = Maybe Word64
type MbMptcpVersion = Maybe Int
type MbMptcpExpectedToken = Maybe Word32

type OptionList = T.Text

    -- deriving (Read, Generic)
type FieldDescriptions = [(T.Text, TsharkFieldDesc)]

baseFields :: FieldDescriptions
baseFields = [
    ("packetid", TsharkFieldDesc "frame.number" [t|Int|] Nothing False)
    -- ("packetid", TsharkFieldDesc "frame.number" [t|Word64|] Nothing False)
    -- ("packetid", TsharkFieldDesc "frame.number" ("packetid" :-> Word64) Nothing False)
    -- ("ifname", TsharkFieldDesc "frame.interface_name" [t|Text|] Nothing False),
    -- ("abstime", TsharkFieldDesc "frame.time_epoch" [t|String|] Nothing False),
    -- , ("ipsrc", TsharkFieldDesc "_ws.col.ipsrc" [t|IP|] (Just "source ip") False)
    -- , ("ipdst", TsharkFieldDesc "_ws.col.ipdst" [t|IP|] (Just "destination ip") False)
    -- , ("tcpstream", TsharkFieldDesc "tcp.stream" [t|Word32|] Nothing False)
    -- , ("mptcpstream", TsharkFieldDesc "mptcp.stream" [t|Word32|] Nothing False)
    -- -- TODO use Word32 instead
    -- , ("sport", TsharkFieldDesc "tcp.srcport" [t|Word16|] Nothing False)
    -- , ("dport", TsharkFieldDesc "tcp.dstport" [t|Word16|] Nothing False)
    -- -- TODO read as a list
    -- ("tcpflags", TsharkFieldDesc "tcp.dstport" [t|String|] Nothing False),
    -- ("tcpoptionkind", TsharkFieldDesc "tcp.dstport" [t|Word32|] Nothing False),
    -- ("tcpseq", TsharkFieldDesc "tcp.seq" [t|Word32|] (Just "Sequence number") False),
    -- ("tcpack", TsharkFieldDesc "tcp.ack" [t|Word32|] (Just "Acknowledgement") False)
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
    False -> return $ Definitely $ Just w64
    where
        w64 = read (T.unpack txt) :: a


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

-- instance Default (ElField MyInt) where def = Field 0
-- instance Default (ElField MyString) where def = Field ""
-- instance Default (ElField MyBool) where def = Field False

-- instance (Applicative f, Default a) => Default (f a) where def = pure def
-- instance Default (f (g a)) => Default (Compose f g a) where def = Compose def

-- instance RecPointed Default f ts => Default (Rec f ts) where
--   def = rpointMethod @Default def

getHeaders :: [(T.Text, TsharkFieldDesc)] -> [(T.Text, Q Type)]
getHeaders = map (\(name, x) -> (name, colType x))

headersFromFields :: [(T.Text, TsharkFieldDesc)] -> Q [(T.Text, Q Type)]
headersFromFields fields = do
  pure (getHeaders fields)
