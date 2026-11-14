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
  , _keystream_into
  ) where

import Control.Monad.ST (runST)
import Crypto.Cipher.ChaCha20 (Error(..))
import qualified Crypto.Cipher.ChaCha20 as ChaCha20
import qualified Crypto.Cipher.ChaCha20.Native as Native
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word8, Word32, Word64)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)

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
--   The counter must leave room for the requested number of bytes.
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
  -> Word64         -- ^ number of bytes
  -> Either Error BS.ByteString -- ^ keystream
keystream r key@(BI.PS kfp koff kl) counter nonce@(BI.PS nfp noff nl) len
  | kl /= 32   = Left InvalidKey
  | nl /= 12   = Left InvalidNonce
  | len > room = Left CounterOverflow
  | Native.chacha20_native_available =
      Right $ BI.unsafeCreate (fi len) $ \dst ->
        withForeignPtr kfp $ \kp ->
        withForeignPtr nfp $ \np ->
          Native.keystream_into (drounds r) (kp `plusPtr` koff) counter
            (np `plusPtr` noff) dst (fi len)
  | otherwise = Right $ runST $
      ChaCha20._cipher_rounds (drounds r)
        (ChaCha20._parse_key key) counter (ChaCha20._parse_nonce nonce)
        (BS.replicate (fi len) 0)
  where
    !room = (0x100000000 - fi counter) * 64 :: Word64

-- | Write keystream bytes to the destination pointer, for the key and
--   nonce at the given pointers.
--
--   Unchecked: the key and nonce pointers must address 32 and 12
--   bytes respectively, the destination must have room for the given
--   number of bytes, and the counter must leave room for them.
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
