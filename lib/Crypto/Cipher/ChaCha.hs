{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UnboxedTuples #-}

module Crypto.Cipher.ChaCha where

import qualified Data.Bits as B
import Data.Bits ((.|.), (.<<.), (.^.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Control.Monad.Primitive (PrimMonad, PrimState)
import Data.Foldable (for_)
import qualified Data.Primitive.PrimArray as PA
import Foreign.ForeignPtr
import GHC.Exts
import GHC.Word

-- utils ----------------------------------------------------------------------

-- keystroke saver
fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- parse strict ByteString in LE order to Word32 (verbatim from
-- Data.Binary)
unsafe_word32le :: BS.ByteString -> Word32
unsafe_word32le s =
  (fi (s `BU.unsafeIndex` 3) `B.unsafeShiftL` 24) .|.
  (fi (s `BU.unsafeIndex` 2) `B.unsafeShiftL` 16) .|.
  (fi (s `BU.unsafeIndex` 1) `B.unsafeShiftL`  8) .|.
  (fi (s `BU.unsafeIndex` 0))
{-# INLINE unsafe_word32le #-}

data WSPair = WSPair
  {-# UNPACK #-} !Word32
  {-# UNPACK #-} !BS.ByteString

-- variant of Data.ByteString.splitAt that behaves like an incremental
-- Word32 parser
unsafe_parseWsPair :: BS.ByteString -> WSPair
unsafe_parseWsPair (BI.BS x l) =
  WSPair (unsafe_word32le (BI.BS x 4)) (BI.BS (plusForeignPtr x 4) (l - 4))
{-# INLINE unsafe_parseWsPair #-}

-- chacha quarter round -------------------------------------------------------

-- RFC8439 2.2
quarter
  :: PrimMonad m
  => ChaCha (PrimState m)
  -> Int
  -> Int
  -> Int
  -> Int
  -> m ()
quarter (ChaCha m) i0 i1 i2 i3 = do
  !(W32# a) <- PA.readPrimArray m i0
  !(W32# b) <- PA.readPrimArray m i1
  !(W32# c) <- PA.readPrimArray m i2
  !(W32# d) <- PA.readPrimArray m i3

  let !(# a1, b1, c1, d1 #) = quarter# a b c d

  PA.writePrimArray m i0 (W32# a1)
  PA.writePrimArray m i1 (W32# b1)
  PA.writePrimArray m i2 (W32# c1)
  PA.writePrimArray m i3 (W32# d1)

-- for easy testing
quarter'
  :: Word32 -> Word32 -> Word32 -> Word32 -> (Word32, Word32, Word32, Word32)
quarter' (W32# a) (W32# b) (W32# c) (W32# d) =
  let !(# a', b', c', d' #) = quarter# a b c d
  in  (W32# a', W32# b', W32# c', W32# d')
{-# INLINE quarter' #-}

-- RFC8439 2.1
quarter#
  :: Word32# -> Word32# -> Word32# -> Word32#
  -> (# Word32#, Word32#, Word32#, Word32# #)
quarter# a b c d =
  let a0 = plusWord32# a b
      d0 = xorWord32# d a0
      d1 = rotateL# d0 16#

      c0 = plusWord32# c d1
      b0 = xorWord32# b c0
      b1 = rotateL# b0 12#

      a1 = plusWord32# a0 b1
      d2 = xorWord32# d1 a1
      d3 = rotateL# d2 8#

      c1 = plusWord32# c0 d3
      b2 = xorWord32# b1 c1
      b3 = rotateL# b2 7#

  in  (# a1, b3, c1, d3 #)
{-# INLINE quarter# #-}

rotateL# :: Word32# -> Int# -> Word32#
rotateL# w i
  | isTrue# (i ==# 0#) = w
  | otherwise = wordToWord32# (
            ((word32ToWord# w) `uncheckedShiftL#` i)
      `or#` ((word32ToWord# w) `uncheckedShiftRL#` (32# -# i)))
{-# INLINE rotateL# #-}

-- key and nonce parsing ------------------------------------------------------

data Key = Key {
    k0 :: {-# UNPACK #-} !Word32
  , k1 :: {-# UNPACK #-} !Word32
  , k2 :: {-# UNPACK #-} !Word32
  , k3 :: {-# UNPACK #-} !Word32
  , k4 :: {-# UNPACK #-} !Word32
  , k5 :: {-# UNPACK #-} !Word32
  , k6 :: {-# UNPACK #-} !Word32
  , k7 :: {-# UNPACK #-} !Word32
  }
  deriving (Eq, Show)

-- parse strict 256-bit bytestring (length unchecked) to key
parse_key :: BS.ByteString -> Key
parse_key bs =
  let !(WSPair k0 t0) = unsafe_parseWsPair bs
      !(WSPair k1 t1) = unsafe_parseWsPair t0
      !(WSPair k2 t2) = unsafe_parseWsPair t1
      !(WSPair k3 t3) = unsafe_parseWsPair t2
      !(WSPair k4 t4) = unsafe_parseWsPair t3
      !(WSPair k5 t5) = unsafe_parseWsPair t4
      !(WSPair k6 t6) = unsafe_parseWsPair t5
      !(WSPair k7 t7) = unsafe_parseWsPair t6
  in  if   BS.null t7
      then Key {..}
      else error "ppad-chacha (parse_key): bytes remaining"

data Nonce = Nonce {
    n0 :: {-# UNPACK #-} !Word32
  , n1 :: {-# UNPACK #-} !Word32
  , n2 :: {-# UNPACK #-} !Word32
  }
  deriving (Eq, Show)

-- parse strict 96-bit bytestring (length unchecked) to nonce
parse_nonce :: BS.ByteString -> Nonce
parse_nonce bs =
  let !(WSPair n0 t0) = unsafe_parseWsPair bs
      !(WSPair n1 t1) = unsafe_parseWsPair t0
      !(WSPair n2 t2) = unsafe_parseWsPair t1
  in  if   BS.null t2
      then Nonce {..}
      else error "ppad-chacha (parse_nonce): bytes remaining"

-- chacha20 block function ----------------------------------------------------

newtype ChaCha s = ChaCha (PA.MutablePrimArray s Word32)
  deriving Eq

chacha
  :: PrimMonad m
  => Key
  -> Word32
  -> Nonce
  -> m (ChaCha (PrimState m))
chacha key counter nonce = do
  state <- _chacha_alloc
  _chacha_set state key counter nonce
  pure state

-- allocate a new chacha state
_chacha_alloc :: PrimMonad m => m (ChaCha (PrimState m))
_chacha_alloc = fmap ChaCha (PA.newPrimArray 16)
{-# INLINE _chacha_alloc #-}

-- XX can be optimised more (only change counter)

-- set the values of a chacha state
_chacha_set
  :: PrimMonad m
  => ChaCha (PrimState m)
  -> Key
  -> Word32
  -> Nonce
  -> m ()
_chacha_set (ChaCha arr) Key {..} counter Nonce {..}= do
  PA.writePrimArray arr 00 0x61707865
  PA.writePrimArray arr 01 0x3320646e
  PA.writePrimArray arr 02 0x79622d32
  PA.writePrimArray arr 03 0x6b206574
  PA.writePrimArray arr 04 k0
  PA.writePrimArray arr 05 k1
  PA.writePrimArray arr 06 k2
  PA.writePrimArray arr 07 k3
  PA.writePrimArray arr 08 k4
  PA.writePrimArray arr 09 k5
  PA.writePrimArray arr 10 k6
  PA.writePrimArray arr 11 k7
  PA.writePrimArray arr 12 counter
  PA.writePrimArray arr 13 n0
  PA.writePrimArray arr 14 n1
  PA.writePrimArray arr 15 n2
{-# INLINEABLE _chacha_set #-}

_chacha_counter
  :: PrimMonad m
  => ChaCha (PrimState m)
  -> Word32
  -> m ()
_chacha_counter (ChaCha arr) counter =
  PA.writePrimArray arr 12 counter

-- two full rounds (eight quarter rounds)
rounds :: PrimMonad m => ChaCha (PrimState m) -> m ()
rounds state = do
  quarter state 00 04 08 12
  quarter state 01 05 09 13
  quarter state 02 06 10 14
  quarter state 03 07 11 15
  quarter state 00 05 10 15
  quarter state 01 06 11 12
  quarter state 02 07 08 13
  quarter state 03 04 09 14
{-# INLINEABLE rounds #-}

_block
  :: PrimMonad m
  => ChaCha (PrimState m)
  -> Word32
  -> m BS.ByteString
_block state@(ChaCha s) counter = do
  _chacha_counter state counter
  i <- PA.freezePrimArray s 0 16
  for_ [1..10 :: Int] (const (rounds state))
  for_ [0..15 :: Int] $ \idx -> do
    let iv = PA.indexPrimArray i idx
    sv <- PA.readPrimArray s idx
    PA.writePrimArray s idx (iv + sv)
  serialize state

serialize :: PrimMonad m => ChaCha (PrimState m) -> m BS.ByteString
serialize (ChaCha m) = do
    w64_0 <- w64 <$> PA.readPrimArray m 00 <*> PA.readPrimArray m 01
    w64_1 <- w64 <$> PA.readPrimArray m 02 <*> PA.readPrimArray m 03
    w64_2 <- w64 <$> PA.readPrimArray m 04 <*> PA.readPrimArray m 05
    w64_3 <- w64 <$> PA.readPrimArray m 06 <*> PA.readPrimArray m 07
    w64_4 <- w64 <$> PA.readPrimArray m 08 <*> PA.readPrimArray m 09
    w64_5 <- w64 <$> PA.readPrimArray m 10 <*> PA.readPrimArray m 11
    w64_6 <- w64 <$> PA.readPrimArray m 12 <*> PA.readPrimArray m 13
    w64_7 <- w64 <$> PA.readPrimArray m 14 <*> PA.readPrimArray m 15
    pure . BS.toStrict . BSB.toLazyByteString . mconcat $
      [w64_0, w64_1, w64_2, w64_3, w64_4, w64_5, w64_6, w64_7]
  where
    w64 a b = BSB.word64LE (fi a .|. (fi b .<<. 32))

-- chacha20 encryption --------------------------------------------------------

encrypt
  :: PrimMonad m
  => BS.ByteString
  -> Word32
  -> BS.ByteString
  -> BS.ByteString
  -> m BS.ByteString
encrypt raw_key@(BI.PS _ _ kl) counter raw_nonce@(BI.PS _ _ nl) plaintext
  | kl /= 32  = error "ppad-chacha (encrypt): invalid key"
  | nl /= 12  = error "ppad-chacha (encrypt): invalid nonce"
  | otherwise = do
      let key = parse_key raw_key
          non = parse_nonce raw_nonce
      _encrypt key counter non plaintext

_encrypt
  :: PrimMonad m
  => Key
  -> Word32
  -> Nonce
  -> BS.ByteString
  -> m BS.ByteString
_encrypt key counter nonce plaintext = do
  ChaCha initial <- chacha key counter nonce
  state@(ChaCha s) <- _chacha_alloc

  let loop acc !j bs = case BS.splitAt 64 bs of
        (chunk@(BI.PS _ _ l), etc)
          | l == 0 && BS.length etc == 0 -> pure $
              BS.toStrict (BSB.toLazyByteString acc)
          | otherwise -> do
              PA.copyMutablePrimArray s 0 initial 0 16
              stream <- _block state j
              let cip = BS.packZipWith (.^.) chunk stream
              loop (acc <> BSB.byteString cip) (j + 1) etc

  loop mempty counter plaintext
{-# INLINE _encrypt #-}

