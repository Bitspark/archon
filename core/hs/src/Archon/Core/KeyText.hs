-- | The canonical spelling of a public key: @ed25519:@ followed by 64 lowercase hex digits.
--
-- Encoding always produces lowercase. Decoding accepts either case in the digits, as the Go
-- reference does (@hex.DecodeString@), but the prefix is exact: @ED25519:@ is not archon's
-- spelling. The oracle pins only ENCODING here — decoding is held to the Go reference by reading
-- it, not by a vector.
module Archon.Core.KeyText
  ( keyTextPrefix
  , encodeKey
  , decodeKey
  ) where

import Archon.Core.Crypto (publicKeySize)
import Archon.Core.HexBytes (fixedFromHex, toHex)
import qualified Data.ByteString as B
import Data.Text (Text)
import qualified Data.Text as T

keyTextPrefix :: Text
keyTextPrefix = T.pack "ed25519:"

encodeKey :: B.ByteString -> Text
encodeKey publicKey = keyTextPrefix <> toHex publicKey

decodeKey :: Text -> Maybe B.ByteString
decodeKey text = T.stripPrefix keyTextPrefix text >>= fixedFromHex publicKeySize
