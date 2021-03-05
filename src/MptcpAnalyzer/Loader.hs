module MptcpAnalyzer.Loader
where

-- TODO return an Either or Maybe ?
loadPcapIntoFrame :: Members [Cache, Log String, Embed IO ] m => TsharkParams -> FilePath -> Sem m (Maybe SomeFrame)
loadPcapIntoFrame params path = do
    log $ "Start loading pcap " ++ path
    x <- getCache cacheId
    case x of
      Right frame -> do
          log $ show cacheId ++ " in cache"
          return $ Just frame
      Left err -> do
          log $ "getCache error: " ++ err
          log "Calling tshark"
          -- TODO need to create a temporary file
          -- mkstemps
          -- TODO use showCommandForUser to display the run command to the user
          -- , stdOut, stdErr)
          (tempPath , exitCode, stdErr) <- liftIO $ withTempFileEx opts "/tmp" "mptcp.csv" (exportToCsv params path)
          if exitCode == ExitSuccess
              then do
                log $ "exported to file " ++ tempPath
                frame <- liftIO $ loadRows tempPath
                log $ "Number of rows after loading " ++ show (frameLength frame)
                cacheRes <- putCache cacheId frame
                -- use ifThenElse instead
                if cacheRes then
                  log "Saved into cache"
                else
                  pure ()
                return $ Just frame
              else do
                log $ "Error happened: " ++ show exitCode
                log stdErr
                log "error happened: exitCode"
                return Nothing

    where
      cacheId = CacheId [path] "" ""
      opts :: TempFileOptions
      opts = TempFileOptions True

