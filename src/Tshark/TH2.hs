{-# LANGUAGE OverloadedStrings #-}
module Tshark.TH2
where
import Tshark.Fields
import Language.Haskell.TH
import Frames.TH
import Frames.CSV
import Data.Text hiding (map)
import Data.Proxy (Proxy(..))
-- import MptcpAnalyzer.Types
import Tshark.TH

-- myColumnUniverse :: FieldDescriptions -> Q Type
-- myColumnUniverse fields = do
--     colTys <- mapM (\(_name, x) -> colType x) fields
--     return $ recDec colTys
-- mkColSynDec (myColumnUniverse baseFields) (mkName "toto")
-- type MyType = $(myColumnUniverse baseFields)
  --
-- myColumnUniverse "MptcpColumnUniverse" baseFields
-- TODO
--
-- type  MptcpColumnUniverse = [Int]
-- type MptcpColumnUniverse = [Bool, Int, Double]


-- myRow :: RowGen [Bool, Int, Double]
-- myRow = (RowGen {
--     columnNames = map (unpack . fst) baseFields
--     , tablePrefix = ""
--     , separator = pack "|"
--     , rowTypeName = "HostCols"
--     , columnUniverse = Proxy
--     , lineReader =  produceTokens ""
--     })

-- declarePrefixedColumns "" baseFields



-- getHeaders :: [(T.Text, TsharkFieldDesc)] -> [(T.Text, Q Type)]
-- getHeaders = map (\(name, x) -> (name, colType x))

-- headersFromFields :: [(T.Text, TsharkFieldDesc)] -> Q [(T.Text, Q Type)]
-- myHeaders :: [(Text, Q Type)]
-- myHeaders = getHeaders baseFields
-- myHeaders = headersFromFields baseFields
-- headersFromFields :: [(T.Text, TsharkFieldDesc)] -> Q [(T.Text, Q Type)]
-- headersFromFields fields = do
--   pure (getHeaders fields)
