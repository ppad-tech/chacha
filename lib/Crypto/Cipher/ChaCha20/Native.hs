{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE BangPatterns #-}

-- |
-- Module: Crypto.Cipher.ChaCha20.Native
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Vectorised ChaCha20, via ARM NEON, or x86 SSE2 and AVX2.

module Crypto.Cipher.ChaCha20.Native (
    chacha20_native_available
  , block
  , cipher
  , keystream_into
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import Data.Word (Word8, Word32)
import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- ffi ------------------------------------------------------------------------

foreign import ccall unsafe "chacha20_block_native"
  c_chacha20_block
    :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> CInt -> IO ()

foreign import ccall unsafe "chacha20_cipher_native"
  c_chacha20_cipher
    :: Ptr Word8 -> Word32 -> Ptr Word8
    -> Ptr Word8 -> Ptr Word8 -> CSize -> CInt -> IO ()

foreign import ccall unsafe "chacha20_native_available"
  c_chacha20_native_available :: IO CInt

-- utilities ------------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- api ------------------------------------------------------------------------

-- | Is a vectorised kernel available?
chacha20_native_available :: Bool
chacha20_native_available =
  unsafeDupablePerformIO c_chacha20_native_available /= 0
{-# NOINLINE chacha20_native_available #-}

-- | One 64-byte keystream block, using the given number of double
--   rounds, for the given (already-validated) key, counter, and nonce.
block
  :: Int -> BS.ByteString -> Word32 -> BS.ByteString -> BS.ByteString
block drounds (BI.PS kfp koff _) counter (BI.PS nfp noff _) =
  BI.unsafeCreate 64 $ \dst ->
    withForeignPtr kfp $ \kp0 ->
    withForeignPtr nfp $ \np0 ->
      c_chacha20_block (kp0 `plusPtr` koff)
                       counter
                       (np0 `plusPtr` noff)
                       dst
                       (fi drounds)

-- | XOR the plaintext with the keystream derived, using the given
--   number of double rounds, from the given (already-validated) key,
--   counter, and nonce.
cipher
  :: Int -> BS.ByteString -> Word32 -> BS.ByteString -> BS.ByteString
  -> BS.ByteString
cipher drounds (BI.PS kfp koff _) counter (BI.PS nfp noff _)
       (BI.PS pfp poff plen) =
  BI.unsafeCreate plen $ \dst ->
    withForeignPtr kfp $ \kp0 ->
    withForeignPtr nfp $ \np0 ->
    withForeignPtr pfp $ \pp0 ->
      c_chacha20_cipher (kp0 `plusPtr` koff)
                        counter
                        (np0 `plusPtr` noff)
                        (pp0 `plusPtr` poff)
                        dst
                        (fi plen)
                        (fi drounds)

-- | Write 'len' bytes of keystream, using the given number of double
--   rounds, for the 32-byte key and 12-byte nonce at the given
--   pointers, to the destination, which must not overlap them. The
--   counter must leave room for 'len' bytes.
keystream_into
  :: Int -> Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Int
  -> IO ()
keystream_into drounds kp counter np dst len = do
  fillBytes dst 0 len
  c_chacha20_cipher kp counter np dst dst (fi len) (fi drounds)
