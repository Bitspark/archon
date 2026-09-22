-- | Lowercase hex out, case-insensitive hex in, at exactly the length a value must have.
--
-- Decoding is fixed-size on purpose: a seed is 64 digits and a signature 128, and a string of
-- the wrong length is refused rather than truncated or padded. No @0x@ prefix, no whitespace.
module Archon.Core.HexBytes
  ( toHex
  , seedFromHex
  , pubkeyFromHex
  , signatureFromHex
  , fixedFromHex
  ) where

import Archon.Core.Crypto (publicKeySize, seedSize, signatureSize)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString as B
import Data.Char (ord)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word8)

toHex :: B.ByteString -> Text
toHex = T.pack . concatMap byte . B.unpack
  where
    byte b = [digit (b `shiftR` 4), digit (b .&. 0x0F)]
    digit n = "0123456789abcdef" !! fromIntegral n

seedFromHex, pubkeyFromHex, signatureFromHex :: Text -> Maybe B.ByteString
seedFromHex = fixedFromHex seedSize
pubkeyFromHex = fixedFromHex publicKeySize
signatureFromHex = fixedFromHex signatureSize

fixedFromHex :: Int -> Text -> Maybe B.ByteString
fixedFromHex size text
  | T.length text /= size * 2 = Nothing
  | otherwise = B.pack <$> pairs (T.unpack text)
  where
    pairs (hi : lo : rest) = (:) <$> byte hi lo <*> pairs rest
    pairs [] = Just []
    pairs _ = Nothing
    byte hi lo = (\h l -> h `shiftL` 4 .|. l) <$> value hi <*> value lo

value :: Char -> Maybe Word8
value c
  | c >= '0' && c <= '9' = Just (fromIntegral (ord c - ord '0'))
  | c >= 'a' && c <= 'f' = Just (fromIntegral (ord c - ord 'a' + 10))
  | c >= 'A' && c <= 'F' = Just (fromIntegral (ord c - ord 'A' + 10))
  | otherwise = Nothing
