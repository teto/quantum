{-# LANGUAGE FlexibleInstances                      #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Types
where


import Net.IP
import Frames.TH
import Frames
import Frames.ShowCSV
import Frames.CSV (QuotingMode(..), ParserOptions(..))
import Frames.ColumnTypeable (Parseable(..), parseIntish, Parsed(..))
import Data.Word (Word16, Word32, Word64)
import qualified Data.Text as T
import Net.Tcp ( TcpFlag(..), numberToTcpFlags)
import Frames.InCore (VectorFor)
import qualified Data.Vector as V
import Numeric (readHex)

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

-- type ManMaybe = Rec (Maybe :. ElField) ManColumns
-- TODO goal here is to choose the most performant Data.Vector
type instance VectorFor Word16 = V.Vector
type instance VectorFor Word32 = V.Vector
type instance VectorFor Word64 = V.Vector
type instance VectorFor IP = V.Vector
type instance VectorFor TcpFlagList = V.Vector
