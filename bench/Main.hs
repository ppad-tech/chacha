{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import qualified Crypto.Cipher.ChaCha20 as ChaCha20
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Maybe (fromJust)

main :: IO ()
main = defaultMain [
    suite
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

suite :: Benchmark
suite =
  bgroup "ppad-chacha" [
    bench "cipher" $ nf (ChaCha20.cipher key 1 non) plain
  ]

