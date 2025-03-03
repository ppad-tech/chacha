{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}

module Crypto.Cipher.ChaCha where

import qualified Data.Bits as B
import Data.Bits ((.^.))
import Data.Word (Word32)
import GHC.Exts

