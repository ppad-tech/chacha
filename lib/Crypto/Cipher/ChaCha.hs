{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UnboxedTuples #-}

module Crypto.Cipher.ChaCha where

import qualified Data.Bits as B
import Data.Bits ((.|.))
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
--
-- invariant:
--   the input bytestring is at least 32 bits in length
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
--
-- invariant:
--   the input bytestring is at least 32 bits in length
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

-- chacha block function ------------------------------------------------------

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

parse_nonce :: BS.ByteString -> Nonce
parse_nonce bs =
  let !(WSPair n0 t0) = unsafe_parseWsPair bs
      !(WSPair n1 t1) = unsafe_parseWsPair t0
      !(WSPair n2 t2) = unsafe_parseWsPair t1
  in  if   BS.null t2
      then Nonce {..}
      else error "ppad-chacha (parse_nonce): bytes remaining"

newtype ChaCha s = ChaCha (PA.MutablePrimArray s Word32)
  deriving Eq

-- init chacha state
chacha
  :: PrimMonad m
  => BS.ByteString
  -> Word32
  -> BS.ByteString
  -> m (ChaCha (PrimState m))
chacha key counter nonce = do
  arr <- PA.newPrimArray 16
  PA.writePrimArray arr 00 0x61707865
  PA.writePrimArray arr 01 0x3320646e
  PA.writePrimArray arr 02 0x79622d32
  PA.writePrimArray arr 03 0x6b206574

  let Key {..} = parse_key key
  PA.writePrimArray arr 04 k0
  PA.writePrimArray arr 05 k1
  PA.writePrimArray arr 06 k2
  PA.writePrimArray arr 07 k3
  PA.writePrimArray arr 08 k4
  PA.writePrimArray arr 09 k5
  PA.writePrimArray arr 10 k6
  PA.writePrimArray arr 11 k7

  PA.writePrimArray arr 12 counter

  let Nonce {..} = parse_nonce nonce
  PA.writePrimArray arr 13 n0
  PA.writePrimArray arr 14 n1
  PA.writePrimArray arr 15 n2

  pure (ChaCha arr)


rounds
  :: PrimMonad m
  => ChaCha (PrimState m)
  -> m ()
rounds state = do
  quarter state 00 04 08 12
  quarter state 01 05 09 13
  quarter state 02 06 10 14
  quarter state 03 07 11 15
  quarter state 00 05 10 15
  quarter state 01 06 11 12
  quarter state 02 07 08 13
  quarter state 03 04 09 14

serialize
  :: PrimMonad m
  => ChaCha (PrimState m)
  -> m BS.ByteString
serialize (ChaCha m) = do
  let loop acc j
        | j == 16 = pure (BS.toStrict (BSB.toLazyByteString acc))
        | otherwise = do
            v <- PA.readPrimArray m j
            loop (acc <> BSB.word32LE v) (j + 1)
  loop mempty 0

chacha20_block
  :: PrimMonad m
  => BS.ByteString
  -> Word32
  -> BS.ByteString
  -> m BS.ByteString
chacha20_block key counter nonce = do
  state@(ChaCha s) <- chacha key counter nonce
  i <- PA.freezePrimArray s 0 16
  for_ [1..10 :: Int] (const (rounds state))
  for_ [0..15 :: Int] $ \idx -> do
    let !iv = PA.indexPrimArray i idx
    sv <- PA.readPrimArray s idx
    PA.writePrimArray s idx (iv + sv)
  serialize state



