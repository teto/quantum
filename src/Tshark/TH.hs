{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell            #-}
module Tshark.TH
where

import Tshark.Fields
import MptcpAnalyzer.Types

import qualified Data.Text as T
import Language.Haskell.TH
import Language.Haskell.TH.Syntax (Q)
import GHC.TypeLits
import Net.IP
import Control.Arrow (second)
import Data.Word (Word16, Word32, Word64)
-- import Language.Haskell.TH.Syntax
import Data.Vinyl ()
-- sequenceQ
-- sequenceQ
import Language.Haskell.TH.Syntax (sequenceQ, Q)
-- for ( (:->)())
import Frames.Col ()
-- ((:->))
import Frames
import Frames.TH hiding (tablePrefix, rowTypeName)
-- import Frames
import Frames.Utils
import Data.Proxy (Proxy(..))
import Control.Monad (foldM)

-- for symbol
-- import GHC.Types


-- genRow :: [ TsharkFieldDesc ] -> Q Type
-- genRow fields = rowTy
--   where f field = fullname field :-> colType field
--         rowTy = TySynD (mkName rowTypeName) [] (recDec colTypes)

-- mkColSynDec

-- baseFields :: [(String, TsharkFieldDesc)]
-- type MyColumns =  SkillLevel ': NumericalAnswer ': CommonColumns
-- frame.number,frame.interface_name,frame.time_epoch,_ws.col.ipsrc,_ws.col.ipdst,ip.src_host,ip.dst_host,tcp.stream,tcp.srcport,tcp.dstport,tcp.flags,tcp.option_kind,tcp.seq,tcp.len,tcp.ack


-- mptcpFields :: [TsharkField]
-- mptcpFields = [
--         -- # TODO use 'category'
--         -- # rawvalue is tcp.window_size_value
--         -- # tcp.window_size takes into account scaling factor !
--         Field "tcp.window_size" "rwnd" 'Int64' True True
--         Field "tcp.flags" "tcpflags" 'UInt8' False True _convert_flags
--         Field "tcp.option_kind" "tcpoptions" None False False
--             -- functools.partial(_load_list field="option_kind") )
--         Field "tcp.seq" "tcpseq" 'UInt32' "TCP sequence number" True
--         Field "tcp.len" "tcplen" 'UInt16' "TCP segment length" True
--         Field "tcp.ack" "tcpack" 'UInt32' "TCP segment acknowledgment" True
--         Field "tcp.options.timestamp.tsval" "tcptsval" 'Int64'
--             "TCP timestamp tsval" True
--         Field "tcp.options.timestamp.tsecr" "tcptsecr" 'Int64'
--             "TCP timestamp tsecr" True
--     ]

declareColumns :: FieldDescriptions -> DecsQ
declareColumns fields = do
  foldM toto ([]) fields
  where
    -- acc ++
    toto acc (name, field) = do
      t <- declareColumn name (colType field)
      return $ acc ++ t

-- "user id" :-> Int
-- getTypes :: [(T.Text, TsharkFieldDesc)] -> [Q Type]
-- getTypes = map (\(_, x) -> colType x)


-- headersFromFields :: [(T.Text, TsharkFieldDesc)] -> Q [(T.Text, Q Type)]
-- headersFromFields fields = do
--   pure (getHeaders fields)


-- Q Type ?
-- colType
-- colTypeQ = [t|$(litT . strTyLit $ T.unpack colName) :-> $(return colTy)|]
-- declareColumns :: [(Text, TsharkFieldDesc)] -> [(Symbol, *)]
-- declareColumns = map (\(name, x) -> name :: Symbol  :-> colType x)

-- declarePcapColumn = [t|$(litT . strTyLit $ T.unpack colName) :-> $(return colTy)|]

-- TODO make public in Frames
-- table
mkColDecs :: T.Text -> Either (String -> Q [Dec]) Type -> Q (Type, [Dec])
mkColDecs colNm colTy = do
  let tablePrefix = ""
  let rowTypeName = "toto"
  let safeName = tablePrefix ++ (T.unpack . sanitizeTypeName $ colNm)
  mColNm <- lookupTypeName safeName
  case mColNm of
    Just n -> pure (ConT n, []) -- Column's type was already defined
    Nothing -> colDec (T.pack tablePrefix) rowTypeName colNm colTy


-- | Generate a column type.
-- recDecExplicit :: [(T.Text, Q Type)] -> Q Type
-- recDecExplicit = appT [t|Record|] . go
--   where go [] = return PromotedNilT
--         go ((n,t):cs) =
--           [t|($(litT $ strTyLit (T.unpack n)) :-> $t) ': $(go cs) |]

-- TODO pass on rowTypeName
-- myRowGen :: String -> [(T.Text, TsharkFieldDesc)] -> DecsQ
-- myRowGen rowName fields = do
--   rowType <- recDecExplicit tfields
--   -- let recTy = TySynD (mkName rowTypeName) [] (recDec colTypes)
--   let recTy = TySynD (mkName rowName) [] rowType
--   colDecs <- concat <$> mapM (uncurry $ colDecExplicit (T.pack tablePrefix)) headers
--   return [recTy]
--   where
--       tfields = map (\(colName, fullField) -> (colName, colType fullField)) fields
--

--myRow :: [(T.Text, TsharkFieldDesc)] -> RowGen a
--myRow fields = RowGen [] "" "|" "ManColumnsTshark" []
--  where
--    --
--    tfields = map (\(colName, fullField) -> (colName, colType fullField)) fields

-- type CommonColumns = [Bool, Int, Double, T.Text]
-- rowGen :: FilePath -> RowGen CommonColumns

-- myColumnUniverse :: String -> FieldDescriptions -> Q [Dec]
-- myColumnUniverse rowTypeName fields = do
--     let colTys = map (\(_name, x) -> colType x) fields
--     colTypes <- tySynD (mkName rowTypeName) [] (promotedTypeList colTys)
--     -- colTypes <- sequenceQ colTys
--     -- f <- sequenceA (colTypes)
--     return [colTypes]
--     -- return $ tySynD colTys
--     -- where
--     --   colTypes :: Q Type


promotedTypeList :: [Q Type] -> Q Type
promotedTypeList []     = promotedNilT
promotedTypeList (t:ts) = [t| $promotedConsT $t $(promotedTypeList ts) |]

-- myColumnUniverse baseFields
-- recDecExplicit fields

-- tableTypesExplicitFull headers RowGen {..} = do
-- declareMyRow :: [(T.Text, TsharkFieldDesc)] -> String -> Q Exp
-- declareMyRow fields rowName = do
--     tableTypesExplicitFull tfields myRow
--     where
--       -- myRow :: RowGen [t| myColumnUniverse baseFields|]
--       myRow = RowGen $(myColumnUniverse baseFields) "" "|" "ManColumnsTshark" (Proxy  [Int, Int])
--       tfields = map (\(colName, fullField) -> (colName, colType fullField)) fields

-- colDec :: prefix rowName colName colTypeGen = do
-- colDec prefix rowName colName colTypeGen = do

-- forall a c.
-- mapM (colDec rowName
-- declareRow :: String -> [(T.Text, TsharkFieldDesc)] -> DecsQ
-- declareRow rowTypeName fields = do
--   -- return a list of
--   -- record type recTy
--   -- optsDec 
--   -- let recTy = TySynD (mkName rowTypeName) [] (recDec colTypes)
--   -- mapM (colDec rowName
--     -- colName,
--   headers <- mapM (\(_colName, fullField) -> (colType fullField)) fields
--   (colTypes, colDecs) <- (second concat . unzip)
--                         <$> mapM (uncurry mkColDecs)
--                                   (map (second colType) headers)
--   return (recTy : colDecs)
--   where
--       -- mkColDecs :: T.Text -> Either (String -> Q [Dec]) Type -> Q (Type, [Dec])
--       recTy = TySynD (mkName rowTypeName) [] (recDec colTypes)

-- tableTypes' (RowGen {..}) =
--   do headers <- runIO . P.runSafeT
--   -- readColHeaders :: m [(T.Text, a)]
--                 $ readColHeaders opts lineSource :: Q [(T.Text, c)]
--      (colTypes, colDecs) <- (second concat . unzip)
--                             <$> mapM (uncurry mkColDecs)
--                                      (map (second colType) headers)
--      let recTy = TySynD (mkName rowTypeName) [] (recDec colTypes)
--          optsName = case rowTypeName of
--                       [] -> error "Row type name shouldn't be empty"
--                       h:t -> mkName $ toLower h : t ++ "Parser"
--      optsTy <- sigD optsName [t|ParserOptions|]
--      optsDec <- valD (varP optsName) (normalB $ lift opts) []
--      return (recTy : optsTy : optsDec : colDecs)
--      -- (:) <$> (tySynD (mkName n) [] (recDec' headers))
--      --     <*> (concat <$> mapM (uncurry $ colDec (T.pack prefix)) headers)
--   where colNames' | null columnNames = Nothing
--                   | otherwise = Just (map T.pack columnNames)
--         opts = ParserOptions colNames' separator (RFC4180Quoting '\"')
--         lineSource = lineReader separator P.>-> P.take prefixSize
--         mkColDecs :: T.Text -> Either (String -> Q [Dec]) Type -> Q (Type, [Dec])
--         mkColDecs colNm colTy = do
--           let safeName = tablePrefix ++ (T.unpack . sanitizeTypeName $ colNm)
--           mColNm <- lookupTypeName safeName
--           case mColNm of
--             Just n -> pure (ConT n, []) -- Column's type was already defined
--             Nothing -> colDec (T.pack tablePrefix) rowTypeName colNm colTy
