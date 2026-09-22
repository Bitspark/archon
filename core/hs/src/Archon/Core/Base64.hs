-- | Standard base64 (RFC 4648 §4), matching Go's @base64.StdEncoding@ — which is what the other
-- cores were measured against. Padding is required and may appear only as one or two @=@ at the
-- very end; @\\r@ and @\\n@ are skipped; any other character outside the alphabet is a refusal
-- rather than something to ignore.
--
-- Written here rather than taken from @base64-bytestring@ so that archon-core depends on boot
-- packages only, and so the rules are visible in one screen rather than inferred from a
-- library's version.
module Archon.Core.Base64
  ( encode
  , decode
  ) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString as B
import Data.Word (Word32, Word8)

alphabet :: B.ByteString
alphabet = B.pack (map (fromIntegral . fromEnum) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

pad :: Word8
pad = 0x3D -- '='

encode :: B.ByteString -> B.ByteString
encode = B.pack . go . B.unpack
  where
    go (a : b : c : rest) = quad a b c 4 ++ go rest
    go [a, b] = quad a b 0 3
    go [a] = quad a 0 0 2
    go [] = []
    -- n = how many of the four output characters are real; the rest are padding
    quad a b c n =
      let chunk = w a `shiftL` 16 .|. w b `shiftL` 8 .|. w c :: Word32
          chars = [chunk `shiftR` 18, chunk `shiftR` 12, chunk `shiftR` 6, chunk]
       in [if i < n then B.index alphabet (fromIntegral (x .&. 0x3F)) else pad | (i, x) <- zip [0 :: Int ..] chars]
    w = fromIntegral :: Word8 -> Word32

decode :: B.ByteString -> Maybe B.ByteString
decode input
  | B.length text `mod` 4 /= 0 = Nothing
  | otherwise = B.pack . concat <$> mapM quad (zip [1 ..] (chunks text))
  where
    text = B.filter (\c -> c /= 0x0D && c /= 0x0A) input
    total = B.length text `div` 4
    chunks bs
      | B.null bs = []
      | otherwise = let (h, t) = B.splitAt 4 bs in h : chunks t

    quad (index, chunk) = do
      let isLast = index == total
          chars = B.unpack chunk
          padding = length (takeWhile (== pad) (reverse chars))
      -- Padding belongs only to the final quad, only in its last two positions, and nothing
      -- but padding may follow it: "AB=C" and "A===" are both refused.
      if padding > 0 && not isLast
        then Nothing
        else do
          let body = take (4 - padding) chars
          if padding > 2 || pad `elem` body
            then Nothing
            else do
              values <- mapM value body
              let vs = values ++ replicate padding 0
                  chunk32 = foldl (\acc v -> acc `shiftL` 6 .|. v) 0 vs
                  bytes = [fromIntegral (chunk32 `shiftR` 16), fromIntegral (chunk32 `shiftR` 8), fromIntegral chunk32]
              Just (take (3 - padding) bytes)

value :: Word8 -> Maybe Word32
value c
  | c >= 0x41 && c <= 0x5A = Just (fromIntegral (c - 0x41))
  | c >= 0x61 && c <= 0x7A = Just (fromIntegral (c - 0x61 + 26))
  | c >= 0x30 && c <= 0x39 = Just (fromIntegral (c - 0x30 + 52))
  | c == 0x2B = Just 62
  | c == 0x2F = Just 63
  | otherwise = Nothing
