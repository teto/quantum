{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DerivingStrategies         #-}
-- {-# LANGUAGE DerivingVia         #-}
-- {-# LANGUAGE DerivingStrategies         #-}
module Tshark.Fields
where
import MptcpAnalyzer.Stream

import Net.Tcp (TcpFlag(..))
import Net.IP
import Net.IPv6 (IPv6(..))
import GHC.TypeLits (KnownSymbol)
import Language.Haskell.TH (Name)
import Data.Text (Text)
import Data.Word (Word8, Word16, Word32, Word64)
import Frames.ShowCSV

-- Phantom types
-- data Mptcp
-- data Tcp
-- -- data Protocol = Tcp | Mptcp
-- -- type TcpFlagList = [TcpFlag]

-- -- TODO use Word instead
-- newtype StreamId a = StreamId Word32 deriving (Show, Read, Eq, Ord )

-- type StreamIdTcp = StreamId Tcp
-- type StreamIdMptcp = StreamId Mptcp

type TcpFlagList = [TcpFlag]


type MbMptcpStream = Maybe (StreamId Mptcp)
type MbMptcpSendKey = Maybe Word64
type MbMptcpVersion = Maybe Int
type MbMptcpExpectedToken = Maybe Word32

type MbMptcpDsn = Maybe Word64
type MbMptcpDack = Maybe Word64
type MbWord64 = Maybe Word64

data TsharkFieldDesc = TsharkFieldDesc {
        fullname :: Text
        -- ^Test
        , colType :: Name
        -- , colType :: Q Type
        , label :: Maybe Text
        -- ^How to reference it in plot
        , hash :: Bool
        -- ^Wether to take into account this field when creating a hash of a packet
    }

    -- deriving (Read, Generic)
type FieldDescriptions = [(Text, TsharkFieldDesc)]

type MbWord32 = Maybe Word32

-- MUST BE KEPT IN SYNC WITH  Pcap.hs ManColumnsTshark
-- ORDER INCLUDED !
-- until we can automate this
-- get Name
baseFields :: FieldDescriptions
baseFields = [
    ("packetId", TsharkFieldDesc "frame.number" ''Word64 Nothing False)
    , ("interfaceName", TsharkFieldDesc "frame.interface_name" ''Text Nothing False)
    , ("absTime", TsharkFieldDesc "frame.time_epoch" ''Text Nothing False)
    , ("relTime", TsharkFieldDesc "frame.time_relative" ''Double Nothing False)
    , ("ipSource", TsharkFieldDesc "_ws.col.ipsrc" ''IP (Just "source ip") False)
    , ("ipDest", TsharkFieldDesc "_ws.col.ipdst" ''IP (Just "destination ip") False)
    , ("ipsrcHost", TsharkFieldDesc "ip.src_host" ''Text (Just "source ip hostname") False)
    , ("ipdstHost", TsharkFieldDesc "ip.dst_host" ''Text (Just "destination ip hostname") False)
    , ("tcpStream", TsharkFieldDesc "tcp.stream" ''StreamIdTcp Nothing False)
    , ("tcpSrcPort", TsharkFieldDesc "tcp.srcport" ''Word16 Nothing False)
    , ("tcpDestPort", TsharkFieldDesc "tcp.dstport" ''Word16 Nothing False)
    , ("rwnd", TsharkFieldDesc "tcp.window_size" ''Word32 Nothing False)
    -- -- TODO use Word32 instead
    -- -- TODO read as a list TcpFlagList
    , ("tcpFlags", TsharkFieldDesc "tcp.flags" ''TcpFlagList Nothing False)
    , ("tcpOptionKinds", TsharkFieldDesc "tcp.option_kind" ''Text Nothing False)
    , ("tcpSeq", TsharkFieldDesc "tcp.seq" ''Word32 (Just "Sequence number") False)
    , ("tcpLen", TsharkFieldDesc "tcp.len" ''Word16 (Just "Tcp Len") False)
    , ("tcpAck", TsharkFieldDesc "tcp.ack" ''Word32 (Just "Tcp ACK") False)

    , ("tsval", TsharkFieldDesc "tcp.options.timestamp.tsval" ''MbWord32 (Just "Timestamp val") False)
    , ("tsecr", TsharkFieldDesc "tcp.options.timestamp.tsecr" ''MbWord32 (Just "Timestamp echo-reply") False)

    , ("mptcpExpectedToken", TsharkFieldDesc "mptcp.expected_token" ''MbMptcpExpectedToken (Just "Expected token") False)

    , ("mptcpStream", TsharkFieldDesc "mptcp.stream" ''MbMptcpStream Nothing False)
    , ("mptcpSendKey", TsharkFieldDesc "tcp.options.mptcp.sendkey" ''MbWord64 Nothing False)
    , ("mptcpRecvKey", TsharkFieldDesc "tcp.options.mptcp.recvkey" ''MbWord64 Nothing False)
    , ("mptcpRecvToken", TsharkFieldDesc "tcp.options.mptcp.recvtok" ''MbMptcpExpectedToken Nothing False)
    -- TODO bool
    , ("mptcpDataFin", TsharkFieldDesc "tcp.options.mptcp.datafin.flag" ''MbWord64 Nothing False)
    , ("mptcpVersion", TsharkFieldDesc "tcp.options.mptcp.version" ''MbMptcpVersion Nothing False)
    , ("mptcpDack", TsharkFieldDesc "mptcp.ack" ''MbWord64 Nothing False)
    , ("mptcpDsn", TsharkFieldDesc "mptcp.dsn" ''MbWord64 Nothing False)

    ]


