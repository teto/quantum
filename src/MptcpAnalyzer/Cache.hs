{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module MptcpAnalyzer.Cache
where

import MptcpAnalyzer.Pcap
import Data.List (intercalate)
import System.FilePath.Posix (takeBaseName)

import Polysemy

data CacheId = CacheId {
  cacheDeps :: [FilePath]
  , cachePrefix :: String
  , cacheSuffix :: String
} deriving (Show, Eq)

data CacheConfig = CacheConfig {
  cacheFolder :: [FilePath]
  , cacheEnabled :: Bool
} deriving Show


getFilenameFromCacheId :: CacheId -> FilePath
getFilenameFromCacheId cid =
    cachePrefix cid ++ intercalate "_" basenames ++ hash ++ cacheSuffix cid
    where
        -- takeBaseName
        basenames = map takeBaseName $ cacheDeps cid
        -- TODO
        hash = "hash"


-- TODO add a cacheConfig ?
-- TODO this should be an effect
data Cache m a where
    -- should maybe be a filepath
    PutCache :: CacheId -> FilePath -> Cache m Bool
    GetCache :: CacheId -> Cache m (Either String PcapFrame)
    IsValid :: CacheId -> Cache m Bool

makeSem ''Cache

-- TODO pass cache config
runCache :: CacheConfig -> Sem (Cache : r) a -> Sem r a
runCache config = interpret $ \case
  PutCache cid fp -> doPutCache cid fp
  GetCache cid -> doGetCache config cid
  IsValid cid -> isCacheValid config cid

doGetCache :: CacheConfig -> CacheId -> Sem r (Either String PcapFrame)
doGetCache config cid = do
  return $ Left "getCache not implemented yet"

doPutCache :: CacheId -> FilePath -> Sem r Bool
doPutCache = undefined

isCacheValid :: CacheConfig -> CacheId -> Sem r Bool
isCacheValid config cid = return False

