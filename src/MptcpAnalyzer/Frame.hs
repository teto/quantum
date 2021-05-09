-- TODO reexport stuff ?
module MptcpAnalyzer.Frame
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.Pcap (defaultParserOptions)
import Data.Serialize
import Data.Text as T
import Data.Text.Encoding as TSE
import Data.ByteString as BS
import Frames

import Pipes ((>->))
import qualified Pipes as P
import qualified Pipes.Prelude as P
import qualified Pipes.Parse as P
import qualified Pipes.Safe as P
import qualified Pipes.Safe.Prelude as Safe
import System.IO (Handle, IOMode(ReadMode, WriteMode))
import Data.Vinyl hiding (rget)
import Frames.CSV hiding (consumeTextLines)
import Frames.ShowCSV
-- import Data.Proxy



-- TODO here we want to put a bytestring
instance Serialize (Frame a) where
  -- put f = return $ produceDSV defaultParserOptions f >-> P.map (TSE.encodeUtf8 . T.pack) 
  put f = undefined
  get = undefined

consumeTextLines :: P.MonadSafe m => FilePath -> P.Consumer BS.ByteString m r
consumeTextLines fp = Safe.withFile fp WriteMode $ \h ->
  let loop = P.await >>= P.liftIO . BS.hPut h >> loop
  in loop

-- | Write a header row with column names followed by a line of text
-- for each 'Record' to the given file.
-- doWriteDSV:: (ColumnHeaders ts, Foldable f, RecordToList ts,
--              RecMapMethod ShowCSV ElField ts)
--          => ParserOptions -> FilePath -> f (Record ts) -> IO ()
-- doWriteDSV opts fp recs = P.runSafeT . P.runEffect $
--                    produceDSV opts recs >-> P.map (TSE.encodeUtf8 . T.pack) >-> consumeTextLines fp

