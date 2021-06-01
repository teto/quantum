module MptcpAnalyzer.Debug
where

import Frames
import Frames.CSV
import Data.Vinyl
import Data.Proxy
-- import Data.Text
import Data.List (intercalate)

-- pipeToCSV
-- see https://github.com/acowley/Frames/issues/130
showRow :: (RecMapMethod Show ElField a, RecordToList a)
        => (Record a) -> String
showRow row = intercalate "\t" $ showFields row

showHeader :: forall a . (ColumnHeaders a) => Frame (Record a) -> String
showHeader frame = intercalate "\t" $ columnHeaders (Proxy :: Proxy (Record a))

viewFrame :: (RecMapMethod Show ElField a, RecordToList a, ColumnHeaders a)
          => Frame (Record a) -> IO ()
viewFrame frame = do
  putStrLn $ showHeader frame
  mapM_ (putStrLn . showRow) frame



--
-- embed $ writeCSV "debug.csv" (ffFrame aFrame)
