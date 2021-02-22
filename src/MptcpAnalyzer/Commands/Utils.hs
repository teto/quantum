{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
module MptcpAnalyzer.Commands.Utils
where

-- import Katip
import Polysemy
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Types
-- import Data.Text
import Colog.Polysemy (Log)



import qualified Polysemy.State as P


type DefaultMembers = '[ Log String, Cache, P.State MyState, Embed IO]
