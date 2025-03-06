{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UnboxedTuples #-}

module Main where

import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Foldable (for_)
import qualified Data.Primitive.PrimArray as PA
import Data.Word (Word32)
import Test.Tasty
import qualified Test.Tasty.HUnit as H


main :: IO ()
main = defaultMain $ testGroup "ppad-chacha" [
    quarter
  , quarter_fullstate
  , chacha20_block_init
  , chacha20_rounds
  , chacha20_block
  , chacha20_encrypt
  ]

quarter :: TestTree
quarter = H.testCase "quarter round" $ do
  let e = (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)
      o = ChaCha.quarter' 0x11111111 0x01020304 0x9b8d6f43 0x01234567
  H.assertEqual mempty e o

quarter_fullstate :: TestTree
quarter_fullstate = H.testCase "quarter round (full chacha state)" $ do
  let inp :: PA.PrimArray Word32
      inp = PA.primArrayFromList [
          0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a
        , 0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c
        , 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963
        , 0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
        ]
  hot <- PA.unsafeThawPrimArray inp

  ChaCha.quarter (ChaCha.ChaCha hot) 2 7 8 13

  o <- PA.unsafeFreezePrimArray hot

  let e :: PA.PrimArray Word32
      e = PA.primArrayFromList [
          0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a
        , 0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2
        , 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963
        , 0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320
        ]

  H.assertEqual mempty e o

block_key :: BS.ByteString
block_key =
  case B16.decode "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" of
    Nothing -> error "bang"
    Just k -> k

block_non :: BS.ByteString
block_non =
  case B16.decode "000000090000004a00000000" of
    Nothing -> error "bang"
    Just n -> n

chacha20_block_init :: TestTree
chacha20_block_init = H.testCase "chacha20 state init" $ do
  ChaCha.ChaCha foo <- ChaCha.chacha block_key 1 block_non
  state <- PA.freezePrimArray foo 0 16
  let ref = PA.primArrayFromList [
          0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
        , 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c
        , 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
        , 0x00000001, 0x09000000, 0x4a000000, 0x00000000
        ]
  H.assertEqual mempty ref state

chacha20_rounds :: TestTree
chacha20_rounds = H.testCase "chacha20 20 rounds" $ do
  state@(ChaCha.ChaCha s) <- ChaCha.chacha block_key 1 block_non
  for_ [1..10 :: Int] (const (ChaCha.rounds state))

  out <- PA.freezePrimArray s 0 16

  let ref = PA.primArrayFromList [
          0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f
        , 0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7
        , 0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd
        , 0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2
        ]

  H.assertEqual mempty ref out

chacha20_block :: TestTree
chacha20_block = H.testCase "chacha20 block function" $ do
  o <- ChaCha.chacha20_block block_key 1 block_non
  let raw_exp = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
      e = case B16.decode raw_exp of
        Nothing -> error "bang"
        Just x -> x

  H.assertEqual mempty e o

crypt_plain :: BS.ByteString
crypt_plain = case B16.decode "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e" of
  Nothing -> error "bang"
  Just x -> x

crypt_cip :: BS.ByteString
crypt_cip = case B16.decode "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d" of
  Nothing -> error "bang"
  Just x -> x

crypt_non :: BS.ByteString
crypt_non = case B16.decode "000000000000004a00000000" of
  Nothing -> error "bang"
  Just x -> x

chacha20_encrypt :: TestTree
chacha20_encrypt = H.testCase "chacha20 encrypt" $ do
  o <- ChaCha.chacha20_encrypt block_key 1 crypt_non crypt_plain
  H.assertEqual mempty crypt_cip o





