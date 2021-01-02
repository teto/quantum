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
import Net.Tcp.Definitions (TcpConnection(..))
import Options.Applicative
import Pcap
import Frames
import Control.Lens hiding (argument)
import Polysemy (Member, Members, Sem, Embed)
-- import qualified Polysemy as P
import Polysemy.State as P
import Colog.Polysemy (Log, log)

-- import qualified Pipes.Prelude as P
import Pipes (Producer, (>->))
import qualified Pipes.Prelude as P
import qualified Control.Foldl as L

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

readStreamId :: ReadM (StreamId Tcp)
readStreamId = eitherReader $ \arg -> case reads arg of
  [(r, "")] -> return $ StreamId r
  _ -> Left $ "cannot parse value `" ++ arg ++ "`"

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


-- | Tcp connection
-- TcpConnection
buildConnectionFromTcpStreamId :: PcapFrame -> StreamId Tcp -> Either String Int
buildConnectionFromTcpStreamId frame (StreamId streamId) =
    -- Search for SYN flags
    -- filterFrame
    -- Producer Income m ()
    -- testField = filter
    --           ((> 50) . rgetField @Val))
    --           (testMelt testRec1)
    -- L.genericLength
    -- filterFrame :: RecVec rs => (Record rs -> Bool) -> FrameRec rs -> FrameRec rs

    Right $ filterFrame  (\x -> x ^. tcpStream == streamId) frame

    -- frame >-> P.filter fromStreamId >-> L.genericLength

    -- where
    --       fromStreamId = (== streamId) . view tcpStream

listTcpConnections :: Members [Log String, P.State MyState, Cache, Embed IO] r => ParserListSubflows -> Sem r RetCode
listTcpConnections args = do
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


