{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
module MptcpAnalyzer.Commands.Utils
where

-- import Katip
import Polysemy
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Definitions
-- import Data.Text
import Colog.Polysemy (Log)



import qualified Polysemy.State as P


-- TODO remove IO
-- type DefaultMembers = [Log, Cache, P.State MyState]
type DefaultMembers = '[ Log String, Cache, P.State MyState, Embed IO]
-- TODO because of commands :: HM.Map String (CommandCb m)
-- all commands need to have the same type

-- type CommandCb m = CommandConstraint m => [String] -> Sem m RetCode
