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
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import Data.Word (Word8, Word32)
import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (Ptr, plusPtr)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- ffi ------------------------------------------------------------------------

foreign import ccall unsafe "chacha20_block_native"
  c_chacha20_block
    :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "chacha20_cipher_native"
  c_chacha20_cipher
    :: Ptr Word8 -> Word32 -> Ptr Word8
    -> Ptr Word8 -> Ptr Word8 -> CSize -> IO ()

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

-- | One 64-byte ChaCha20 keystream block for the given (already-
--   validated) key, counter, and nonce.
block :: BS.ByteString -> Word32 -> BS.ByteString -> BS.ByteString
block (BI.PS kfp koff _) counter (BI.PS nfp noff _) =
  BI.unsafeCreate 64 $ \dst ->
    withForeignPtr kfp $ \kp0 ->
    withForeignPtr nfp $ \np0 ->
      c_chacha20_block (kp0 `plusPtr` koff)
                       counter
                       (np0 `plusPtr` noff)
                       dst

-- | XOR the plaintext with the ChaCha20 keystream derived from the
--   given (already-validated) key, counter, and nonce.
cipher
  :: BS.ByteString -> Word32 -> BS.ByteString -> BS.ByteString
  -> BS.ByteString
cipher (BI.PS kfp koff _) counter (BI.PS nfp noff _)
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
