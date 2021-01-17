module Tshark.TH2
where
import Tshark.TH
import Language.Haskell.TH
import Frames.TH
import Frames.CSV
import Data.Text hiding (map)
import Data.Proxy (Proxy(..))

-- myColumnUniverse :: FieldDescriptions -> Q Type
-- myColumnUniverse fields = do
--     colTys <- mapM (\(_name, x) -> colType x) fields
--     return $ recDec colTys
-- mkColSynDec (myColumnUniverse baseFields) (mkName "toto")
-- type MyType = $(myColumnUniverse baseFields)
  --
myColumnUniverse "MptcpColumnUniverse" baseFields
-- TODO
--

myRow :: RowGen MptcpColumnUniverse
myRow = (RowGen {
    columnNames = map (unpack . fst) baseFields
    , tablePrefix = ""
    , separator = pack "|"
    , rowTypeName = "ManColumnsTshark"
    , columnUniverse = Proxy
    , lineReader =  produceTokens ""
    })
