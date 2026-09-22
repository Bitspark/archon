-- | The Haskell core's conformance v1 CLI.
--
--   archon-conformance <family>   reads the whole oracle document on stdin, selects that
--                                 family's cases, RECOMPUTES each one from its inputs, and
--                                 writes one NDJSON line per case.
--
-- It never reads a case's expected value. A CLI that echoed the oracle's @result@ would agree
-- with it by construction and prove nothing; the harness asserts what this computed.
--
-- Input and output are raw UTF-8 bytes, not handles in the locale's encoding: GHC's default
-- handle encoding follows the locale, and a CI container with LANG=C would otherwise fail on the
-- first non-ASCII character in a case's free-text note.
module Main (main) where

import Archon.Core
import qualified Data.ByteString as B
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Json
import System.Environment (getArgs)
import System.Exit (exitWith, ExitCode (..))
import System.IO (hPutStrLn, stderr)

fail' :: String -> IO a
fail' message = hPutStrLn stderr ("conformance: " ++ message) >> exitWith (ExitFailure 1)

main :: IO ()
main = do
  args <- getArgs
  family <- case args of
    [f] -> pure f
    _ -> hPutStrLn stderr "usage: archon-conformance <family>" >> exitWith (ExitFailure 2)
  input <- B.getContents
  document <- either (fail' . ("stdin is not JSON: " ++)) pure (parse (T.unpack (TE.decodeUtf8 input)))
  cases <- case field family document of
    Just (JArray cs) -> pure cs
    _ -> fail' ("no such family: " ++ family)
  outputs <- mapM (line family) [c | c <- cases, Just _ <- [stringField "name" c]]
  B.putStr (TE.encodeUtf8 (T.pack (concat outputs)))

-- | Hex in the ORACLE's inputs is always well-formed; this is transport, not the API under test.
unhex :: String -> B.ByteString
unhex = B.pack . go
  where
    go (a : b : rest) = fromIntegral (digit a * 16 + digit b) : go rest
    go _ = []
    digit c = fromMaybe 0 (lookup c (zip "0123456789abcdefABCDEF" ([0 .. 15] ++ [10 .. 15]))) :: Int

str :: Json -> String -> IO String
str c key = maybe (fail' ("case is missing string field '" ++ key ++ "'")) pure (stringField key c)

-- | The oracle's two-shape result: {"ok": …} or {"error": true}.
result :: Maybe T.Text -> String
result = maybe "{\"error\":true}" (\v -> "{\"ok\":" ++ quote (T.unpack v) ++ "}")

bool :: Bool -> String
bool b = if b then "true" else "false"

line :: String -> Json -> IO String
line family c = do
  name <- str c "name"
  rest <- case family of
    "pubkey_from_seed" -> do
      seed <- unhex <$> str c "seed"
      pure (",\"pubkey\":" ++ quote (maybe "" (T.unpack . toHex) (publicKeyFromSeed seed)))
    "key_encode" -> do
      pub <- unhex <$> str c "pubkey"
      pure (",\"text\":" ++ quote (T.unpack (encodeKey pub)))
    "keycodec" -> do
      kind <- str c "kind"
      value <- case kind of
        "encode_pkcs8" -> seedToPKCS8PEM . unhex <$> str c "key"
        "encode_spki" -> pubkeyToSPKIPEM . unhex <$> str c "key"
        "decode_pkcs8" -> fmap toHex . pkcs8PEMToSeed . T.pack <$> str c "pem"
        "decode_spki" -> fmap toHex . spkiPEMToPubkey . T.pack <$> str c "pem"
        _ -> fail' ("unknown keycodec kind: " ++ kind)
      pure (",\"result\":" ++ result value)
    "signature_verify" -> do
      ok <- verify <$> (unhex <$> str c "pubkey") <*> (unhex <$> str c "message") <*> (unhex <$> str c "sig")
      pure (",\"valid\":" ++ bool ok)
    "hex_decode" -> do
      kind <- str c "kind"
      text <- T.pack <$> str c "hex"
      decoded <- case kind of
        "seed" -> pure (seedFromHex text)
        "pubkey" -> pure (pubkeyFromHex text)
        "signature" -> pure (signatureFromHex text)
        _ -> fail' ("unknown hex_decode kind: " ++ kind)
      pure (",\"result\":" ++ result (toHex <$> decoded))
    "domain_sign" -> do
      sig <- signInDomain <$> (unhex <$> str c "seed") <*> (T.pack <$> str c "domain") <*> (unhex <$> str c "message")
      pure (",\"result\":" ++ result (toHex <$> sig))
    "domain_verify" -> do
      ok <-
        verifyInDomain <$> (unhex <$> str c "pubkey") <*> (T.pack <$> str c "domain")
          <*> (unhex <$> str c "message") <*> (unhex <$> str c "sig")
      pure (",\"valid\":" ++ bool ok)
    _ -> fail' ("unhandled family: " ++ family)
  pure ("{\"name\":" ++ quote name ++ rest ++ "}\n")
