{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}

module Main where

import Control.DeepSeq
import qualified Crypto.Cipher.ChaCha20 as ChaCha20
import qualified Data.ByteString as BS
import GHC.Generics
import Weigh

deriving instance Generic ChaCha20.Error

instance NFData ChaCha20.Error

-- note that 'weigh' doesn't work properly in a repl
main :: IO ()
main = mainWith $ do
  block
  cipher

block :: Weigh ()
block =
  let !key = BS.replicate 32 0x88
      !non = BS.replicate 12 0x00
  in  wgroup "block" $
        func "block" (ChaCha20.block key 1) non

cipher :: Weigh ()
cipher =
  let !key = BS.replicate 32 0x88
      !non = BS.replicate 12 0x00
      !bs0 = BS.replicate 64 0
      !bs1 = BS.replicate 256 0
      !bs2 = BS.replicate 1024 0
      !bs3 = BS.replicate 4096 0
  in  wgroup "cipher" $ do
        func "cipher (64B   input)"
          (ChaCha20.cipher key 1 non) bs0
        func "cipher (256B  input)"
          (ChaCha20.cipher key 1 non) bs1
        func "cipher (1024B input)"
          (ChaCha20.cipher key 1 non) bs2
        func "cipher (4096B input)"
          (ChaCha20.cipher key 1 non) bs3
