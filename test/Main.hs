{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UnboxedTuples #-}

module Main where

import Control.Monad.ST (runST)
import qualified Crypto.Cipher.ChaCha as Reduced
import qualified Crypto.Cipher.ChaCha20 as ChaCha
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Foldable (for_)
import Data.Maybe (fromJust)
import qualified Data.Primitive.PrimArray as PA
import Data.Word (Word8, Word32)
import Foreign.C.Types (CInt(..))
import Foreign.Ptr (Ptr, castPtr)
import Test.Tasty
import qualified Test.Tasty.HUnit as H
import Vectors (V(..), vectors, chacha8rand_seed, chacha8rand_iteration)

main :: IO ()
main = defaultMain $ testGroup "ppad-chacha" [
    quarter
  , quarter_fullstate
  , chacha20_block_init
  , chacha20_rounds
  , encrypt
  , crypt1
  , crypt2
  , crypt3
  , counter_boundary
  , counter_overflow
  , dispatch
  , testGroup "keystream" [
        keystream_vectors
      , keystream_errors
      , keystream_dispatch
      , keystream_into
      ]
  , testGroup "interleaved" [
        interleaved_chacha8rand
      , interleaved_layout
      , interleaved_dispatch
      ]
  , stack_scrub
  ]

quarter :: TestTree
quarter = H.testCase "quarter round" $ do
  let e = (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)
      o = ChaCha._quarter_pure 0x11111111 0x01020304 0x9b8d6f43 0x01234567
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

  ChaCha._quarter (ChaCha.ChaCha hot) 2 7 8 13

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
block_key = fromJust $
  B16.decode "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

block_non :: BS.ByteString
block_non = fromJust $ B16.decode "000000090000004a00000000"

chacha20_block_init :: TestTree
chacha20_block_init = H.testCase "chacha20 state init" $ do
  let key = ChaCha._parse_key block_key
      non = ChaCha._parse_nonce block_non
  ChaCha.ChaCha foo <- ChaCha._chacha key 1 non
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
  let key = ChaCha._parse_key block_key
      non = ChaCha._parse_nonce block_non
  state@(ChaCha.ChaCha s) <- ChaCha._chacha key 1 non
  for_ [1..10 :: Int] (const (ChaCha._rounds state))

  out <- PA.freezePrimArray s 0 16

  let ref = PA.primArrayFromList [
          0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f
        , 0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7
        , 0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd
        , 0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2
        ]

  H.assertEqual mempty ref out

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

encrypt :: TestTree
encrypt = H.testCase "chacha20 encrypt" $ do
  let Right o = ChaCha.cipher block_key 1 crypt_non crypt_plain
  H.assertEqual mempty crypt_cip o

-- additional vectors

crypt1 :: TestTree
crypt1 = H.testCase "chacha20 encrypt (A.2 #1)" $ do
  let key = fromJust . B16.decode $
        "0000000000000000000000000000000000000000000000000000000000000000"
      non = fromJust . B16.decode $
        "000000000000000000000000"
      con = 0
      plain = fromJust . B16.decode $
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      cip = fromJust . B16.decode $
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
      Right out = ChaCha.cipher key con non plain
  H.assertEqual mempty cip out

crypt2 :: TestTree
crypt2 = H.testCase "chacha20 encrypt (A.2 #2)" $ do
  let key = fromJust . B16.decode $
        "0000000000000000000000000000000000000000000000000000000000000001"
      non = fromJust . B16.decode $
        "000000000000000000000002"
      con = 1
      plain = fromJust . B16.decode $
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f"
      cip = fromJust . B16.decode $
        "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221"
      Right out = ChaCha.cipher key con non plain
  H.assertEqual mempty cip out

crypt3 :: TestTree
crypt3 = H.testCase "chacha20 encrypt (A.2 #3)" $ do
  let key = fromJust . B16.decode $
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
      non = fromJust . B16.decode $
        "000000000000000000000002"
      con = 42
      plain = fromJust . B16.decode $
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e"
      cip = fromJust . B16.decode $
        "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"
      Right out = ChaCha.cipher key con non plain
  H.assertEqual mempty cip out

-- counter overflow

overflow_key :: BS.ByteString
overflow_key = fromJust . B16.decode $
  "0000000000000000000000000000000000000000000000000000000000000000"

overflow_non :: BS.ByteString
overflow_non = fromJust . B16.decode $ "000000000000000000000000"

counter_boundary :: TestTree
counter_boundary = H.testCase "chacha20 encrypt (counter boundary)" $ do
  let con = maxBound - 1
      plain = BS.replicate 128 0
      Right b0 = ChaCha.block overflow_key con overflow_non
      Right b1 = ChaCha.block overflow_key maxBound overflow_non
      Right out = ChaCha.cipher overflow_key con overflow_non plain
  H.assertEqual mempty (b0 <> b1) out

counter_overflow :: TestTree
counter_overflow = H.testCase "chacha20 encrypt (counter overflow)" $ do
  let con = maxBound - 1
      plain = BS.replicate 129 0
      out = ChaCha.cipher overflow_key con overflow_non plain
  H.assertEqual mempty (Left ChaCha.CounterOverflow) out

-- dispatching vs pure

-- the dispatching 'cipher' agrees with the pure Haskell implementation
-- for every input length from 0 to 640 bytes, covering partial blocks,
-- short tails, and any multi-block paths. the second counter puts the
-- final block of a 640-byte input at the maximum counter value.
dispatch :: TestTree
dispatch = H.testCase "chacha20 encrypt (dispatch vs pure)" $
  for_ keys $ \key ->
  for_ [1, maxBound - 9] $ \con ->
  for_ [0..640] $ \l -> do
    let msg = BS.take l plain
        Right out = ChaCha.cipher key con block_non msg
        ref = runST $
          ChaCha._cipher (ChaCha._parse_key key) con
                         (ChaCha._parse_nonce block_non) msg
    H.assertEqual ("length " <> show l) ref out
  where
    keys = [block_key, BS.replicate 32 0xff]
    plain = BS.pack [fromIntegral (i * 7 + 3) | i <- [0..639 :: Int]]

-- keystream

hex :: BS.ByteString -> BS.ByteString
hex bs = case B16.decode bs of
  Nothing -> error "ppad-chacha (test): invalid hex"
  Just x  -> x

-- the vectors place a 64-bit IV in the last two words of the state,
-- which is the RFC 8439 layout with a zero first nonce word
keystream_vectors :: TestTree
keystream_vectors = testGroup "draft-strombergson vectors" $
  fmap check vectors
  where
    check V {..} =
      H.testCase (v_case <> " (" <> show v_rounds <> ")") $ do
        let non = BS.replicate 4 0 <> hex v_iv
            out = Reduced.keystream v_rounds (hex v_key) 0 non 128
        H.assertEqual mempty (Right (hex v_keystream)) out

keystream_errors :: TestTree
keystream_errors = H.testCase "keystream errors" $ do
  let key = BS.replicate 32 0
      non = BS.replicate 12 0
  H.assertEqual "key" (Left ChaCha.InvalidKey)
    (Reduced.keystream Reduced.ChaCha8 (BS.take 31 key) 0 non 64)
  H.assertEqual "nonce" (Left ChaCha.InvalidNonce)
    (Reduced.keystream Reduced.ChaCha8 key 0 (BS.take 11 non) 64)
  H.assertEqual "boundary" (Right 128) $
    fmap BS.length
      (Reduced.keystream Reduced.ChaCha8 key (maxBound - 1) non 128)
  H.assertEqual "overflow" (Left ChaCha.CounterOverflow)
    (Reduced.keystream Reduced.ChaCha8 key (maxBound - 1) non 129)
  H.assertEqual "zero length" (Right mempty)
    (Reduced.keystream Reduced.ChaCha8 key 0 non 0)
  H.assertEqual "negative length" (Right mempty)
    (Reduced.keystream Reduced.ChaCha8 key 0 non (-1))

-- the dispatching 'keystream' agrees with the pure Haskell
-- implementation for every round count and every length from 0 to
-- 640 bytes
keystream_dispatch :: TestTree
keystream_dispatch = H.testCase "keystream (dispatch vs pure)" $
  for_ rounds $ \(r, d) ->
  for_ [1, maxBound - 9] $ \con ->
  for_ [0..640] $ \l -> do
    let Right out = Reduced.keystream r block_key con block_non l
        ref = runST $
          ChaCha._cipher_rounds d (ChaCha._parse_key block_key) con
            (ChaCha._parse_nonce block_non) (BS.replicate l 0)
    H.assertEqual (show r <> ", length " <> show l) ref out
  where
    rounds = [(Reduced.ChaCha8, 4), (Reduced.ChaCha12, 6),
              (Reduced.ChaCha20, 10)]

keystream_into :: TestTree
keystream_into = H.testCase "_keystream_into" $
  for_ [Reduced.ChaCha8, Reduced.ChaCha12, Reduced.ChaCha20] $ \r -> do
    let Right ref = Reduced.keystream r block_key 7 block_non 1000
    out <- BI.create 1000 $ \dst ->
      BU.unsafeUseAsCString block_key $ \kp ->
      BU.unsafeUseAsCString block_non $ \np ->
        Reduced._keystream_into r (castPtr kp) 7 (castPtr np) dst 1000
    H.assertEqual (show r) ref out

-- interleaved

type Interleave =
     Reduced.Rounds -> Reduced.FeedForward -> Ptr Word8 -> Word32
  -> Ptr Word8 -> Ptr Word8 -> Int -> IO ()

interleave
  :: Interleave -> Reduced.Rounds -> Reduced.FeedForward -> BS.ByteString
  -> Word32 -> BS.ByteString -> Int -> IO BS.ByteString
interleave f r ff key con non groups =
  BI.create (256 * groups) $ \dst ->
    BU.unsafeUseAsCString key $ \kp ->
    BU.unsafeUseAsCString non $ \np ->
      f r ff (castPtr kp) con (castPtr np) dst groups

-- ChaCha8Rand's iteration is sixteen ChaCha8 blocks, interleaved, with
-- the key-only final addition; its first 992 bytes are output
interleaved_chacha8rand :: TestTree
interleaved_chacha8rand = H.testCase "ChaCha8Rand iteration" $ do
  out <- interleave Reduced._interleaved_into Reduced.ChaCha8
           Reduced.FeedForwardKey chacha8rand_seed 0 (BS.replicate 12 0) 4
  H.assertEqual mempty (hex chacha8rand_iteration) (BS.take 992 out)

-- with the full final addition, the output is the standard keystream
-- with each group of four blocks transposed
interleaved_layout :: TestTree
interleaved_layout = H.testCase "layout (vs keystream)" $
  for_ [Reduced.ChaCha8, Reduced.ChaCha12, Reduced.ChaCha20] $ \r -> do
    let Right ks = Reduced.keystream r block_key 7 block_non (256 * 3)
        word b i = BS.take 4 (BS.drop (64 * b + 4 * i) ks)
        ex = BS.concat [ word (4 * g + j) i
                       | g <- [0 .. 2], i <- [0 .. 15], j <- [0 .. 3] ]
    out <- interleave Reduced._interleaved_into r Reduced.FeedForwardAll
             block_key 7 block_non 3
    H.assertEqual (show r) ex out

-- the dispatching '_interleaved_into' agrees with the pure Haskell
-- implementation; the second counter puts the final block of six
-- groups at the maximum counter value
interleaved_dispatch :: TestTree
interleaved_dispatch = H.testCase "dispatch vs pure" $
  for_ [Reduced.ChaCha8, Reduced.ChaCha12, Reduced.ChaCha20] $ \r ->
  for_ [Reduced.FeedForwardAll, Reduced.FeedForwardKey] $ \ff ->
  for_ [block_key, BS.replicate 32 0xff] $ \key ->
  for_ [1, maxBound - 23] $ \con ->
  for_ [1 .. 6] $ \groups -> do
    out <- interleave Reduced._interleaved_into r ff key con block_non
             groups
    ref <- interleave Reduced._interleaved_pure_into r ff key con
             block_non groups
    H.assertEqual (show (r, ff, con, groups)) ref out

-- stack scrubbing

foreign import ccall unsafe "chacha_test_remnant"
  c_test_remnant :: CInt -> CInt -> IO CInt

-- no native kernel leaves its key in the stack region it used, for
-- each round count (see test/remnant.c); on platforms without native
-- kernels the check is vacuous
stack_scrub :: TestTree
stack_scrub = H.testCase "native kernels scrub the stack" $
  for_ [0 .. 6] $ \which ->
  for_ [4, 6, 10] $ \drounds -> do
    r <- c_test_remnant which drounds
    H.assertEqual (show (kernel which, drounds)) 0 r
  where
    kernel :: CInt -> String
    kernel w = case w of
      0 -> "block"
      1 -> "cipher (100B)"
      2 -> "cipher (300B)"
      3 -> "cipher (1024B)"
      4 -> "one interleaved group"
      5 -> "three interleaved groups"
      _ -> "four interleaved groups"
