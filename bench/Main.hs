{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}

module Main where

import Control.DeepSeq
import Criterion.Main
import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.Cipher.ChaCha20 as ChaCha20
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Maybe (fromJust)
import Foreign.Ptr (castPtr)
import GHC.Generics

deriving instance Generic ChaCha20.Error

instance NFData ChaCha20.Error

main :: IO ()
main = defaultMain [
    suite
  , keystream
  , interleaved
  ]

plain :: BS.ByteString
plain = fromJust . B16.decode $
  "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"

key :: BS.ByteString
key = fromJust . B16.decode $
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

non :: BS.ByteString
non = fromJust . B16.decode $
  "000000090000004a00000000"

plain_1k :: BS.ByteString
plain_1k = BS.replicate 1024 0x42

plain_4k :: BS.ByteString
plain_4k = BS.replicate 4096 0x42

suite :: Benchmark
suite =
  bgroup "ppad-chacha" [
    bench "cipher" $ nf (ChaCha20.cipher key 1 non) plain
  , bench "cipher (1024B)" $ nf (ChaCha20.cipher key 1 non) plain_1k
  , bench "cipher (4096B)" $ nf (ChaCha20.cipher key 1 non) plain_4k
  ]

keystream :: Benchmark
keystream =
  bgroup "ppad-chacha (keystream, 1024B)" [
    bench "ChaCha8" $ nf (ChaCha.keystream ChaCha.ChaCha8 key 1 non) 1024
  , bench "ChaCha12" $ nf (ChaCha.keystream ChaCha.ChaCha12 key 1 non) 1024
  , bench "ChaCha20" $ nf (ChaCha.keystream ChaCha.ChaCha20 key 1 non) 1024
  ]


interleaved :: Benchmark
interleaved =
  bgroup "ppad-chacha (interleaved, 1024B)" [
    bench "ChaCha8" $ nfIO (inter ChaCha.ChaCha8 ChaCha.FeedForwardKey)
  , bench "ChaCha20" $ nfIO (inter ChaCha.ChaCha20 ChaCha.FeedForwardAll)
  ]
  where
    inter r ff = BI.create 1024 $ \dst ->
      BU.unsafeUseAsCString key $ \kp ->
      BU.unsafeUseAsCString non $ \np ->
        ChaCha._interleaved_into r ff (castPtr kp) 1 (castPtr np) dst 4
