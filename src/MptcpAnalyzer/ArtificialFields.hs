module MptcpAnalyzer.ArtificialFields
where
import MptcpAnalyzer.Stream

import Net.IP
-- import Net.IPv6 (IPv6(..))
import GHC.TypeLits (KnownSymbol)
-- import Language.Haskell.TH (Name)
import Data.Text (Text)
-- import Data.Word (Word8, Word16, Word32, Word64)
import Frames.ShowCSV
import Tshark.Fields

-- |Filters a connection depending on its role
data ConnectionRole = RoleServer | RoleClient deriving (Show, Eq, Enum, Read, ShowCSV, Ord)

artificialFields :: FieldDescriptions
artificialFields = [
    ("tcpDest", TsharkFieldDesc "" ''ConnectionRole Nothing False)
    , ("mptcpDest", TsharkFieldDesc "" ''ConnectionRole Nothing False)
    , ("packetHash", TsharkFieldDesc "" ''ConnectionRole Nothing False)
  ]
