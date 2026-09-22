{-# LANGUAGE ForeignFunctionInterface #-}

-- | Ed25519 key derivation, signing and verification, raw and domain-separated.
--
-- Domain separation is Ed25519ph with the domain as the RFC 8032 §5.1 context string. The
-- prefix enters BOTH the nonce hash and the challenge hash, so it cannot be layered over a pure
-- @sign message@ — which is why this module binds OpenSSL rather than crypton, whose Ed25519 has
-- no hash or context selection.
--
-- Verification enforces ADR 0008 before the equation runs: the public key and R must each be
-- canonical encodings of points of order exactly L, and S must be below L. That is why
-- libsodium is linked as well — OpenSSL validates no points for Ed25519.
--
-- Refusal is 'Nothing' or 'False', never an exception: the oracle's protocol has two outcomes,
-- and so does this API. Every function is pure; the calls into the shim are deterministic.
module Archon.Core.Crypto
  ( seedSize
  , publicKeySize
  , signatureSize
  , maxDomainSize
  , publicKeyFromSeed
  , sign
  , verify
  , signInDomain
  , verifyInDomain
  , librariesMeetFloors
  ) where

import qualified Data.ByteString as B
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Word (Word8)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, castPtr)
import System.IO.Unsafe (unsafeDupablePerformIO)

seedSize, publicKeySize, signatureSize :: Int
seedSize = 32
publicKeySize = 32
signatureSize = 64

-- | A domain is 1–255 BYTES of UTF-8 — counted in bytes, as every core counts it. A
-- character-counting core would accept 255-character domains the others refuse.
maxDomainSize :: Int
maxDomainSize = 255

foreign import ccall unsafe "archon_crypto.h archon_libraries_ok"
  c_libraries_ok :: IO CInt
foreign import ccall unsafe "archon_crypto.h archon_public_key_from_seed"
  c_public_key_from_seed :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "archon_crypto.h archon_sign"
  c_sign :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "archon_crypto.h archon_verify"
  c_verify :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "archon_crypto.h archon_sign_in_domain"
  c_sign_in_domain :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "archon_crypto.h archon_verify_in_domain"
  c_verify_in_domain :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

-- | Whether the OpenSSL and libsodium this process LOADED meet archon's floors. When they do
-- not, every function here refuses: signing nothing and accepting nothing is the only safe
-- behaviour for a core that cannot enforce its own profile.
librariesMeetFloors :: Bool
librariesMeetFloors = unsafeDupablePerformIO $ (== 1) <$> c_libraries_ok

-- | A ByteString's bytes as a pointer and length. An empty ByteString may yield a null pointer;
-- the shim treats (NULL, 0) as an empty message.
withBytes :: B.ByteString -> (Ptr Word8 -> CSize -> IO a) -> IO a
withBytes bs k = B.useAsCStringLen bs $ \(p, n) -> k (castPtr p) (fromIntegral n)

-- | Run a shim call that fills an n-byte output buffer; keep the buffer only on success.
withOutput :: Int -> (Ptr Word8 -> IO CInt) -> Maybe B.ByteString
withOutput n call = unsafeDupablePerformIO $ allocaBytes n $ \out -> do
  rc <- call out
  if rc == 1 then Just <$> B.packCStringLen (castPtr out, n) else pure Nothing

publicKeyFromSeed :: B.ByteString -> Maybe B.ByteString
publicKeyFromSeed seed
  | B.length seed /= seedSize = Nothing
  | otherwise = withOutput publicKeySize $ \out ->
      withBytes seed $ \s _ -> c_public_key_from_seed s out

sign :: B.ByteString -> B.ByteString -> Maybe B.ByteString
sign seed message
  | B.length seed /= seedSize = Nothing
  | otherwise = withOutput signatureSize $ \out ->
      withBytes seed $ \s _ -> withBytes message $ \m ml -> c_sign s m ml out

verify :: B.ByteString -> B.ByteString -> B.ByteString -> Bool
verify publicKey message signature
  | B.length publicKey /= publicKeySize || B.length signature /= signatureSize = False
  | otherwise = unsafeDupablePerformIO $
      withBytes publicKey $ \p _ -> withBytes message $ \m ml -> withBytes signature $ \g _ ->
        (== 1) <$> c_verify p m ml g

signInDomain :: B.ByteString -> Text -> B.ByteString -> Maybe B.ByteString
signInDomain seed domain message
  | B.length seed /= seedSize || not (domainOK context) = Nothing
  | otherwise = withOutput signatureSize $ \out ->
      withBytes seed $ \s _ -> withBytes context $ \d dl -> withBytes message $ \m ml ->
        c_sign_in_domain s d dl m ml out
  where
    context = TE.encodeUtf8 domain

verifyInDomain :: B.ByteString -> Text -> B.ByteString -> B.ByteString -> Bool
verifyInDomain publicKey domain message signature
  | B.length publicKey /= publicKeySize || B.length signature /= signatureSize = False
  | not (domainOK context) = False
  | otherwise = unsafeDupablePerformIO $
      withBytes publicKey $ \p _ -> withBytes context $ \d dl -> withBytes message $ \m ml ->
        withBytes signature $ \g _ -> (== 1) <$> c_verify_in_domain p d dl m ml g
  where
    context = TE.encodeUtf8 domain

domainOK :: B.ByteString -> Bool
domainOK context = not (B.null context) && B.length context <= maxDomainSize
