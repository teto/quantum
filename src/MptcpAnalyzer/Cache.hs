{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module MptcpAnalyzer.Cache
where

import MptcpAnalyzer.Pcap
import Data.List (intercalate)
import System.FilePath.Posix (takeBaseName)
import Frames
import System.Directory
import Polysemy

data CacheId = CacheId {
  cacheDeps :: [FilePath]
  , cachePrefix :: String
  , cacheSuffix :: String
} deriving (Show, Eq)

data CacheConfig = CacheConfig {
  cacheFolder :: FilePath
  , cacheEnabled :: Bool
} deriving Show


filenameFromCacheId :: CacheId -> FilePath
filenameFromCacheId cid =
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
    PutCache :: CacheId -> PcapFrame -> Cache m Bool
    GetCache :: CacheId -> Cache m (Either String PcapFrame)
    IsValid :: CacheId -> Cache m Bool

makeSem ''Cache

-- TODO pass cache config
runCache :: Members '[Embed IO] r => CacheConfig -> Sem (Cache : r) a -> Sem r a
runCache config = do
  interpret $ \case
      PutCache cid fp -> doPutCache config cid frame
      GetCache cid -> doGetCache config cid
        -- return $ Left "not implemented"
        -- use config to get the final path too
        -- let csvFilename = filenameFromCacheId cid
        -- rpcap <- embed $ loadRows csvFilename
        -- return Right rpcap
      IsValid cid -> isCacheValid config cid

doGetCache :: Members '[Embed IO] r => CacheConfig -> CacheId -> Sem r (Either String PcapFrame)
doGetCache config cid = do
  res <- embed $ loadRows csvFilename
  return $ Right res
  where
      csvFilename = cacheFolder config ++ "/" ++ filenameFromCacheId cid
  -- return $ Left "getCache not implemented yet"

-- PcapFrame
doPutCache :: CacheConfig -> CacheId -> PcapFrame -> Sem r Bool
doPutCache config cid frame = do
  -- writeFile
  writeCSV
  -- pipeToCsv

-- TODO  log ?
isCacheValid :: Members '[Embed IO] r => CacheConfig -> CacheId -> Sem r Bool
isCacheValid config cid =
  embed $ doesFileExist filename
  where
    filename = cacheFolder config ++ "/" ++ filenameFromCacheId cid
