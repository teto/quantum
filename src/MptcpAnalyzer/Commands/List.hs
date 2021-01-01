{-# LANGUAGE FlexibleContexts           #-}

module MptcpAnalyzer.Commands.List
where

-- import Data.Text
-- import Net.Tcp
import Prelude hiding (log)
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.Utils as CMD
import MptcpAnalyzer.Definitions
import Options.Applicative
import Pcap
import Frames
import Control.Lens hiding (argument)
import Polysemy (Member, Members, Sem, Embed)
-- import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)

-- for TcpConnection
-- import Net.Tcp



-- This 

-- |TODO pass the loaded pcap to have a complete filterWith
-- listSubflowParser = 

parserSubflow :: Parser ParserListSubflows
parserSubflow = ParserListSubflows <$> switch
          ( long "full"
         <> help "Print details for each subflow" )
      <*> argument readStreamId (
          metavar "STREAM_ID"
          <> help "Stream Id (tcp.stream)"
          -- TODO pass a default
          )

-- (String -> Either String a) -> ReadM a
readStreamId :: ReadM StreamIdTcp
readStreamId = eitherReader $ \arg -> case reads arg of
  [(r, "")] -> return $ StreamId r
  [(parsed, remain)] -> Left $ "cannot parse value `" ++ arg ++ "' remain" ++ show remain ++ " parsed= " ++ show parsed
  [] -> Left $ "cannot parse value" ++ arg ++ " (empty result)"

listTcpOpts :: Member Command r => ParserInfo (Sem r CMD.RetCode)
listTcpOpts = info (
   CMD.listTcpConnections <$> parserSubflow <**> helper)
  ( progDesc "List subflows of an MPTCP connection"
  )
  -- <> header ""
  -- <> footer ""

-- listTcpConnections :: [TcpConnection] -> Text
-- listTcpConnections conns =
--         streams = self.data.groupby("tcpstream")
--         (show len connections) ++ " tcp connection(s)" ++ map (\
--         where
          -- for tcpstream, group in streams:
          --     con = TcpConnection.build_from_dataframe(self.data, tcpstream)
          --     self.poutput(str(con))
-- checkIfLoaded :: CMD.CommandConstraint m => [String] -> m CMD.RetCode
-- checkIfLoaded = 
    -- putStrLn "not loaded"


-- |
-- buildConnectionFromTcpStreamId :: PcapFrame -> StreamId Tcp -> Maybe TcpConnection
-- buildConnectionFromTcpStreamId frame streamId =
    -- Search for SYN flags
    -- (view tcpstream <$> frame)

listTcpConnections :: Members [Log String, P.State MyState, Cache, Embed IO] r => Sem r RetCode
listTcpConnections = do
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> log "please load a pcap first" >> return CMD.Continue
      Just frame -> do
        let _tcpstreams = getTcpStreams frame
        log $ "Number of rows " ++ show (frameLength frame)
        >> return CMD.Continue


listTcpConnectionsInFrame :: PcapFrame -> IO ()
listTcpConnectionsInFrame frame = do
  putStrLn "Listing tcp connections"
  let streamIds = getTcpStreams frame
  mapM_ print streamIds

  -- L.fold L.minimum (view age <$> ms)
  -- L.fold
  -- putStrLn $ show $ rcast @'[TcpStream] $ frameRow frame 0
  -- let l =  L.fold L.nub (view tcpstream <$> frame)
-- listMptcpConnections :: PcapFrame -> MyStack IO ()
-- listMptcpConnections frame = do
--     return ()


