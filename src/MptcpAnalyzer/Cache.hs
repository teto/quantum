{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module MptcpAnalyzer.Cache
where

import MptcpAnalyzer.Pcap
import Data.List (intercalate)
import System.FilePath.Posix (takeBaseName)
import Frames
import Frames.CSV
import System.Directory
import Polysemy
import Control.Exception as CE

data CacheId = CacheId {
  cacheDeps :: [FilePath]
  , cachePrefix :: String
  , cacheSuffix :: String
} deriving (Show, Eq)

data CacheConfig = CacheConfig {
  cacheFolder :: FilePath
  , cacheEnabled :: Bool
} deriving Show

-- type CachePlaceHolder = Int
type CachePlaceHolder = PcapFrame

filenameFromCacheId :: CacheId -> FilePath
filenameFromCacheId cid =
    cachePrefix cid ++ intercalate "_" basenames ++ hash ++ cacheSuffix cid
    where
        -- takeBaseName
        basenames = map takeBaseName $ cacheDeps cid
        -- TODO
        hash = "hash"

-- Return full path to the config folder
getFullPath :: CacheConfig -> CacheId -> FilePath
getFullPath config cid = cacheFolder config ++ "/" ++ filenameFromCacheId cid

-- TODO add a cacheConfig ?
-- TODO this should be an effect
data Cache m a where
    -- should maybe be a filepath
    PutCache :: CacheId -> CachePlaceHolder -> Cache m Bool
    GetCache :: CacheId -> Cache m (Either String CachePlaceHolder)
    IsValid :: CacheId -> Cache m Bool

makeSem ''Cache

-- TODO pass cache config
runCache :: Members '[Embed IO] r => CacheConfig -> Sem (Cache : r) a -> Sem r a
runCache config = do
  interpret $ \case
      PutCache cid frame -> doPutCache config cid frame
      GetCache cid -> doGetCache config cid 
        -- return $ Left "not implemented"
        -- use config to get the final path too
        -- let csvFilename = filenameFromCacheId cid
        -- rpcap <- embed $ loadRows csvFilename
        -- return Right rpcap
      IsValid cid -> isCacheValid config cid

doGetCache :: Members '[Embed IO] r => CacheConfig -> CacheId -> Sem r (Either String CachePlaceHolder)
doGetCache config cid = do
  -- res <- embed $ loadRows csvFilename
  res <- embed $ CE.try @IOException $  loadRows csvFilename
  case res of
    Left _excpt -> return $ Left "Exception"
    Right x -> return (Right x)

  -- return res
  -- return $ Right res
  -- return $ Right 4
  where
      csvFilename = getFullPath config cid

  -- return $ Left "getCache not implemented yet"

-- PcapFrame
doPutCache :: Members '[Embed IO] r => CacheConfig -> CacheId -> CachePlaceHolder -> Sem r Bool
doPutCache config cid frame =
  -- writeFile
  -- writeCSV :: (ColumnHeaders ts, Foldable f, RecordToList ts, RecMapMethod ShowCSV ElField ts) => FilePath -> f (Record ts) -> IO ()
  embed $ writeCSV csvFilename frame >> return True
  where
      csvFilename = getFullPath config cid

-- TODO  log ?
isCacheValid :: Members '[Embed IO] r => CacheConfig -> CacheId -> Sem r Bool
isCacheValid config cid =
  embed $ doesFileExist filename
  where
    filename = getFullPath config cid
