{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}

-- |
-- Module: Crypto.Cipher.ChaCha
-- Copyright: (c) 2026 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- ChaCha keystreams with 8, 12, or 20 rounds, using the state layout
-- of [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
--
-- The reduced-round variants are intended for uses such as
-- random number generation; use "Crypto.Cipher.ChaCha20" for
-- encryption.

module Crypto.Cipher.ChaCha (
    -- * Round counts
    Rounds(..)

    -- * Keystream
  , keystream

    -- * Error information
  , Error(..)

    -- internal
  , FeedForward(..)
  , _keystream_into
  , _interleaved_into
  , _interleaved_pure_into
  ) where

import Control.Monad.ST (runST)
import Data.Bits ((.|.), (.<<.), (.>>.))
import Crypto.Cipher.ChaCha20 (Error(..))
import qualified Crypto.Cipher.ChaCha20 as ChaCha20
import qualified Crypto.Cipher.ChaCha20.Native as Native
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Foldable (for_)
import Data.Word (Word8, Word32, Word64)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (pokeByteOff)

-- utils ----------------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- rounds ---------------------------------------------------------------------

-- | The number of ChaCha rounds.
data Rounds =
    ChaCha8  -- ^ 8 rounds
  | ChaCha12 -- ^ 12 rounds
  | ChaCha20 -- ^ 20 rounds, as specified by RFC 8439
  deriving (Eq, Show)

-- number of double rounds
drounds :: Rounds -> Int
drounds r = case r of
  ChaCha8  -> 4
  ChaCha12 -> 6
  ChaCha20 -> 10
{-# INLINE drounds #-}

-- keystream ------------------------------------------------------------------

-- | The ChaCha keystream with the given number of rounds, starting
--   at the given block counter.
--
--   The key must be exactly 256 bits, and the nonce exactly 96 bits.
--   The counter must leave room for the requested number of bytes;
--   non-positive numbers of bytes yield the empty string.
--
--   >>> import qualified Data.ByteString as BS
--   >>> import qualified Data.ByteString.Base16 as B16
--   >>> let key = BS.replicate 32 0
--   >>> let non = BS.replicate 12 0
--   >>> fmap B16.encode (keystream ChaCha8 key 0 non 16)
--   Right "3e00ef2f895f40d67f5bb8e81f09a5a1"
keystream
  :: Rounds         -- ^ number of rounds
  -> BS.ByteString  -- ^ 256-bit key
  -> Word32         -- ^ 32-bit counter
  -> BS.ByteString  -- ^ 96-bit nonce
  -> Int            -- ^ number of bytes
  -> Either Error BS.ByteString -- ^ keystream
keystream r key@(BI.PS kfp koff kl) counter nonce@(BI.PS nfp noff nl) len
  | kl /= 32      = Left InvalidKey
  | nl /= 12      = Left InvalidNonce
  | len <= 0      = Right BS.empty
  | fi len > room = Left CounterOverflow
  | Native.chacha20_native_available =
      Right $ BI.unsafeCreate len $ \dst ->
        withForeignPtr kfp $ \kp ->
        withForeignPtr nfp $ \np ->
          Native.keystream_into (drounds r) (kp `plusPtr` koff) counter
            (np `plusPtr` noff) dst len
  | otherwise = Right $ runST $
      ChaCha20._cipher_rounds (drounds r)
        (ChaCha20._parse_key key) counter (ChaCha20._parse_nonce nonce)
        (BS.replicate len 0)
  where
    !room = (0x100000000 - fi counter) * 64 :: Word64

-- | Write keystream bytes to the destination pointer, for the key and
--   nonce at the given pointers.
--
--   Unchecked: the key and nonce pointers must address 32 and 12
--   bytes respectively, the destination must have room for the given
--   number of bytes and must not overlap the key or nonce, and the
--   counter must leave room for the bytes.
_keystream_into
  :: Rounds    -- ^ number of rounds
  -> Ptr Word8 -- ^ 256-bit key
  -> Word32    -- ^ 32-bit counter
  -> Ptr Word8 -- ^ 96-bit nonce
  -> Ptr Word8 -- ^ destination
  -> Int       -- ^ number of bytes
  -> IO ()
_keystream_into r kp counter np dst len
  | Native.chacha20_native_available =
      Native.keystream_into (drounds r) kp counter np dst len
  | otherwise = do
      key <- BS.packCStringLen (castPtr kp, 32)
      non <- BS.packCStringLen (castPtr np, 12)
      let !out = runST $
            ChaCha20._cipher_rounds (drounds r)
              (ChaCha20._parse_key key) counter
              (ChaCha20._parse_nonce non) (BS.replicate len 0)
      BU.unsafeUseAsCString out $ \src ->
        copyBytes dst (castPtr src) len

-- interleaved keystream ------------------------------------------------------

-- | Which words of the input state are added to a block's output.
data FeedForward =
    FeedForwardAll -- ^ all words, as standard
  | FeedForwardKey -- ^ the key words only, omitting the public
                   --   constant, counter, and nonce words, as in
                   --   ChaCha8Rand
  deriving (Eq, Show)

-- | Write groups of four consecutive keystream blocks to the
--   destination pointer, interleaved word by word: within each
--   256-byte group, word i of block j is at byte offset 16 * i + 4 * j.
--   This is the layout that four-way SIMD produces naturally.
--
--   Unchecked: the key and nonce pointers must address 32 and 12
--   bytes respectively, the destination must have room for 256 bytes
--   per group and must not overlap the key or nonce, and the counter
--   must leave room for four blocks per group.
_interleaved_into
  :: Rounds      -- ^ number of rounds
  -> FeedForward -- ^ final addition of the input state
  -> Ptr Word8   -- ^ 256-bit key
  -> Word32      -- ^ 32-bit counter
  -> Ptr Word8   -- ^ 96-bit nonce
  -> Ptr Word8   -- ^ destination
  -> Int         -- ^ number of four-block groups
  -> IO ()
_interleaved_into r ff kp counter np dst groups
  | Native.chacha20_native_available =
      Native.interleaved_into (drounds r) (ff == FeedForwardKey) kp
        counter np dst groups
  | otherwise = _interleaved_pure_into r ff kp counter np dst groups

-- | A pure Haskell '_interleaved_into', with the same preconditions.
_interleaved_pure_into
  :: Rounds
  -> FeedForward
  -> Ptr Word8
  -> Word32
  -> Ptr Word8
  -> Ptr Word8
  -> Int
  -> IO ()
_interleaved_pure_into r ff kp counter np dst groups = do
  key <- BS.packCStringLen (castPtr kp, 32)
  non <- BS.packCStringLen (castPtr np, 12)
  let !ks = runST $
        ChaCha20._cipher_rounds (drounds r)
          (ChaCha20._parse_key key) counter (ChaCha20._parse_nonce non)
          (BS.replicate (256 * groups) 0)
      -- the input word that the final addition omits
      omit i blk = case ff of
        FeedForwardAll -> 0
        FeedForwardKey
          | i < 4     -> constant i
          | i == 12   -> counter + fi blk
          | i > 12    -> le32_at non (4 * (i - 13))
          | otherwise -> 0
  for_ [0 .. groups - 1] $ \g ->
    for_ [0 .. 15] $ \i ->
      for_ [0 .. 3] $ \j -> do
        let !blk = 4 * g + j
            !v   = le32_at ks (64 * blk + 4 * i) - omit i blk
        poke_le32 (dst `plusPtr` (256 * g + 16 * i + 4 * j)) v
  where
    constant :: Int -> Word32
    constant i = case i of
      0 -> 0x61707865
      1 -> 0x3320646e
      2 -> 0x79622d32
      _ -> 0x6b206574

-- little-endian word at the given (in-bounds) offset
le32_at :: BS.ByteString -> Int -> Word32
le32_at bs o =
      fi (BU.unsafeIndex bs o)
  .|. (fi (BU.unsafeIndex bs (o + 1)) .<<. 8)
  .|. (fi (BU.unsafeIndex bs (o + 2)) .<<. 16)
  .|. (fi (BU.unsafeIndex bs (o + 3)) .<<. 24)
{-# INLINE le32_at #-}

poke_le32 :: Ptr Word8 -> Word32 -> IO ()
poke_le32 p w = do
  pokeByteOff p 0 (fi w :: Word8)
  pokeByteOff p 1 (fi (w .>>. 8) :: Word8)
  pokeByteOff p 2 (fi (w .>>. 16) :: Word8)
  pokeByteOff p 3 (fi (w .>>. 24) :: Word8)
{-# INLINE poke_le32 #-}
