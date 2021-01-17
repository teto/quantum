module Tshark.TH2
where
import Tshark.TH
import Language.Haskell.TH
import Frames.TH

-- myColumnUniverse :: FieldDescriptions -> Q Type
-- myColumnUniverse fields = do
--     colTys <- mapM (\(_name, x) -> colType x) fields
--     return $ recDec colTys
-- mkColSynDec (myColumnUniverse baseFields) (mkName "toto")
-- type MyType = $(myColumnUniverse baseFields)
