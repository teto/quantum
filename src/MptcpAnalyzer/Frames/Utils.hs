-- copy/pasted from https://github.com/adamConnerSax/Frames-utils
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
module MptcpAnalyzer.Frames.Utils
where

import qualified Data.Foldable                 as F
import qualified Frames as F
import qualified Frames.Melt                   as F

import qualified Data.Vinyl                    as V
import qualified Data.Vinyl.TypeLevel          as V
import qualified Data.Vinyl.XRec               as V
import           Frames.Melt          (RDeleteAll, ElemOf)

-- |  change a column "name" at the type level
retypeColumn :: forall x y rs. ( V.KnownField x
                               , V.KnownField y
                               , V.Snd x ~ V.Snd y
                               , ElemOf rs x
                               , F.RDelete x rs F.⊆ rs
--                               , Rename (Fst x) (Fst y) rs ~ (RDelete '(Fst x, Snd y) rs ++ '[ '(Fst y, Snd y)]))
                               )
  => F.Record rs -> F.Record (F.RDelete x rs V.++ '[y])
retypeColumn = transform @rs @'[x] @'[y] (\r -> F.rgetField @x r F.&: V.RNil)

-- | replace subset with a calculated different set of fields
transform :: forall rs as bs. (as F.⊆ rs, RDeleteAll as rs F.⊆ rs)
             => (F.Record as -> F.Record bs) -> F.Record rs -> F.Record (RDeleteAll as rs V.++ bs)
transform f xs = F.rcast @(RDeleteAll as rs) xs `F.rappend` f (F.rcast xs)

