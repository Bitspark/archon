-- | SPKI (RFC 5280) and PKCS #8 v1 (RFC 5958) PEM for Ed25519 keys, as fixed DER templates.
--
-- Both formats have exactly one valid shape for an Ed25519 key, so they are handled as a fixed
-- prefix followed by the 32 key bytes — not with a general ASN.1 parser, which would accept
-- encodings the other cores refuse. Anything that does not match the template byte for byte is
-- refused: a v2 PKCS #8 with an embedded public key, a wrong OID, a short key, trailing bytes.
--
-- PEM parsing follows the Go reference exactly: CRLF is accepted, trailing newlines are ignored,
-- the BEGIN and END lines must be the first and last, and the body is standard base64.
module Archon.Core.KeyCodec
  ( pubkeyToSPKIPEM
  , seedToPKCS8PEM
  , spkiPEMToPubkey
  , pkcs8PEMToSeed
  ) where

import qualified Archon.Core.Base64 as Base64
import Archon.Core.Crypto (publicKeySize)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Text (Text)
import qualified Data.Text.Encoding as TE

spkiPrefix, pkcs8Prefix :: B.ByteString
spkiPrefix = B.pack [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]
pkcs8Prefix =
  B.pack
    [0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]

pubkeyToSPKIPEM :: B.ByteString -> Maybe Text
pubkeyToSPKIPEM key = encode key spkiPrefix "PUBLIC KEY"

seedToPKCS8PEM :: B.ByteString -> Maybe Text
seedToPKCS8PEM key = encode key pkcs8Prefix "PRIVATE KEY"

spkiPEMToPubkey :: Text -> Maybe B.ByteString
spkiPEMToPubkey pem = decode pem spkiPrefix "PUBLIC KEY"

pkcs8PEMToSeed :: Text -> Maybe B.ByteString
pkcs8PEMToSeed pem = decode pem pkcs8Prefix "PRIVATE KEY"

encode :: B.ByteString -> B.ByteString -> String -> Maybe Text
encode key prefix pemType
  | B.length key /= publicKeySize = Nothing
  | otherwise =
      Just . TE.decodeUtf8 $
        B.concat
          [ BC.pack ("-----BEGIN " ++ pemType ++ "-----\n")
          , Base64.encode (prefix <> key)
          , BC.pack ("\n-----END " ++ pemType ++ "-----\n")
          ]

decode :: Text -> B.ByteString -> String -> Maybe B.ByteString
decode pem prefix pemType = do
  -- CRLF -> LF, then drop trailing newlines: the Go reference's two normalisations, and no
  -- others. A lone CR survives into the body, where the base64 decoder skips it as Go's does.
  let normalised = dropTrailingNewlines (crlfToLf (TE.encodeUtf8 pem))
      lines' = B.split 0x0A normalised
      begin = BC.pack ("-----BEGIN " ++ pemType ++ "-----")
      end = BC.pack ("-----END " ++ pemType ++ "-----")
  body <- case lines' of
    first : rest@(_ : _ : _)
      | first == begin
      , final : middle <- reverse rest
      , final == end ->
          Just (B.concat (reverse middle))
    _ -> Nothing
  der <- Base64.decode body
  if B.length der /= B.length prefix + publicKeySize || not (prefix `B.isPrefixOf` der)
    then Nothing
    else Just (B.drop (B.length prefix) der)

crlfToLf :: B.ByteString -> B.ByteString
crlfToLf bs = case B.breakSubstring crlf bs of
  (before, rest)
    | B.null rest -> before
    | otherwise -> before <> B.singleton 0x0A <> crlfToLf (B.drop 2 rest)
  where
    crlf = B.pack [0x0D, 0x0A]

dropTrailingNewlines :: B.ByteString -> B.ByteString
dropTrailingNewlines = B.dropWhileEnd (== 0x0A)
