{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
module Commands.Utils
where

-- import Katip
-- import Control.Monad.State (MonadState)
-- import Control.Monad.Trans (MonadIO)
-- import System.Console.Haskeline.MonadException
import Utils
import Data.Text
import Polysemy
import Mptcp.Logging
import Mptcp.Cache

import qualified Polysemy.State as P

data RetCode = Exit | Error Text | Continue

-- TODO remove IO
-- type DefaultMembers = [Log, Cache, P.State MyState]
type DefaultMembers = '[ Log, Cache, P.State MyState, Embed IO]
-- TODO because of commands :: HM.Map String (CommandCb m)
-- all commands need to have the same type

-- type CommandCb m = CommandConstraint m => [String] -> Sem m RetCode
-- type CommandCb = [String] -> Sem DefaultMembers RetCode
type CommandCb r = [String] -> Sem r RetCode
