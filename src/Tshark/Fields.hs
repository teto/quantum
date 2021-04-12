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
import Language.Haskell.TH (Name, Q)
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
        tfieldFullname :: Text
        -- ^Test
        , tfieldColType :: Name
        -- , colType :: Q Type
        , fieldLabel :: Maybe Text
        -- ^How to reference it in plot
        , tfieldHashable :: Bool
        -- ^Wether to take into account this field when creating a hash of a packet
    }

    -- deriving (Read, Generic)
type FieldDescriptions = [(Text, TsharkFieldDesc)]

type MbWord32 = Maybe Word32

-- MUST BE KEPT IN SYNC WITH  Pcap.hs RecTshark
-- ORDER INCLUDED !
-- until we can automate this
-- get Name
baseFields :: FieldDescriptions
baseFields = [
    ("packetId", TsharkFieldDesc "frame.number" ''Word64 Nothing False)
    , ("interfaceName", TsharkFieldDesc "frame.interface_name" ''Text Nothing False)
    , ("absTime", TsharkFieldDesc "frame.time_epoch" ''Double Nothing False)
    , ("relTime", TsharkFieldDesc "frame.time_relative" ''Double Nothing False)
    , ("ipSource", TsharkFieldDesc "_ws.col.ipsrc" ''IP (Just "source ip") True)
    , ("ipDest", TsharkFieldDesc "_ws.col.ipdst" ''IP (Just "destination ip") True)
    , ("ipSrcHost", TsharkFieldDesc "ip.src_host" ''Text (Just "source ip hostname") False)
    , ("ipDstHost", TsharkFieldDesc "ip.dst_host" ''Text (Just "destination ip hostname") False)
    , ("tcpStream", TsharkFieldDesc "tcp.stream" ''StreamIdTcp Nothing False)
    , ("tcpSrcPort", TsharkFieldDesc "tcp.srcport" ''Word16 Nothing True)
    , ("tcpDestPort", TsharkFieldDesc "tcp.dstport" ''Word16 Nothing True)
    , ("rwnd", TsharkFieldDesc "tcp.window_size" ''Word32 Nothing True)
    -- -- TODO use Word32 instead
    -- -- TODO read as a list TcpFlagList
    , ("tcpFlags", TsharkFieldDesc "tcp.flags" ''TcpFlagList Nothing True)
    , ("tcpOptionKinds", TsharkFieldDesc "tcp.option_kind" ''Text Nothing True)
    , ("tcpSeq", TsharkFieldDesc "tcp.seq" ''Word32 (Just "Sequence number") True)
    , ("tcpLen", TsharkFieldDesc "tcp.len" ''Word16 (Just "Tcp Len") True)
    , ("tcpAck", TsharkFieldDesc "tcp.ack" ''Word32 (Just "Tcp ACK") True)

    , ("tsval", TsharkFieldDesc "tcp.options.timestamp.tsval" ''MbWord32 (Just "Timestamp val") True)
    , ("tsecr", TsharkFieldDesc "tcp.options.timestamp.tsecr" ''MbWord32 (Just "Timestamp echo-reply") True)

    , ("mptcpExpectedToken", TsharkFieldDesc "mptcp.expected_token" ''MbMptcpExpectedToken (Just "Expected token") True)

    , ("mptcpStream", TsharkFieldDesc "mptcp.stream" ''MbMptcpStream Nothing False)
    , ("mptcpSendKey", TsharkFieldDesc "tcp.options.mptcp.sendkey" ''MbWord64 Nothing True)
    , ("mptcpRecvKey", TsharkFieldDesc "tcp.options.mptcp.recvkey" ''MbWord64 Nothing True)
    , ("mptcpRecvToken", TsharkFieldDesc "tcp.options.mptcp.recvtok" ''MbMptcpExpectedToken Nothing True)
    -- TODO bool
    , ("mptcpDataFin", TsharkFieldDesc "tcp.options.mptcp.datafin.flag" ''MbWord64 Nothing True)
    , ("mptcpVersion", TsharkFieldDesc "tcp.options.mptcp.version" ''MbMptcpVersion Nothing True)
    , ("mptcpDack", TsharkFieldDesc "mptcp.ack" ''MbWord64 Nothing True)
    , ("mptcpDsn", TsharkFieldDesc "mptcp.dsn" ''MbWord64 Nothing True)

    ]

-- TODO
prefixFields :: FieldDescriptions -> Q FieldDescriptions
prefixFields = 
