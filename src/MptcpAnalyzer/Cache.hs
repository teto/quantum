{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module MptcpAnalyzer.Cache
where

import Pcap
import Data.List (intercalate)
import System.FilePath.Posix (takeBaseName)

import Polysemy

data CacheId = CacheId {
  cacheDeps :: [FilePath]
  , cachePrefix :: String
  , cacheSuffix :: String
}


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

runCache :: Sem (Cache : r) a -> Sem r a
runCache = interpret $ \case
  PutCache cid fp -> doPutCache cid fp
  GetCache cid -> doGetCache cid
  IsValid cid -> isCacheValid cid

doGetCache :: CacheId -> Sem r (Either String PcapFrame)
doGetCache _cacheItemId = return $ Left "getCache not implemented yet"

doPutCache :: CacheId -> FilePath -> Sem r Bool
doPutCache = undefined

isCacheValid :: CacheId -> Sem r Bool
isCacheValid  _ = return False

