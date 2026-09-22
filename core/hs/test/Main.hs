-- | Unit tests for what the oracle cannot express. Its protocol has two outcomes per case — ok
-- or error — so argument SHAPE failures (a 31-byte seed, a 256-byte domain) and the byte-versus-
-- character count of a domain have nowhere to go there. The signatures themselves are the
-- oracle's job, through conformance/harness.mjs.
--
-- No test framework: plain assertions keep the suite, like the library, on boot packages only.
-- Every PRINTED string here is ASCII: stdout is encoded in the locale's encoding, and a CI
-- container running under LANG=C throws on the first non-ASCII character it is asked to print.
module Main (main) where

import Archon.Core
import Control.Monad (unless)
import qualified Data.ByteString as B
import Data.IORef
import Data.Maybe (fromJust, isJust, isNothing)
import qualified Data.Text as T
import System.Exit (exitFailure)

main :: IO ()
main = do
  failures <- newIORef (0 :: Int)
  let check what ok = do
        putStrLn ((if ok then "  ok    " else "  FAIL  ") ++ what)
        unless ok (modifyIORef failures (+ 1))

      seed = B.pack [0 .. 31]
      pub = fromJust (publicKeyFromSeed seed)
      msg = B.pack (map (fromIntegral . fromEnum) "hello")
      domain = T.pack "archon/test/v1"

  -- If this fails, everything else does too, by design. This line says why.
  check "the loaded libraries meet archon's floors" librariesMeetFloors

  check "a 31-byte seed is refused" (isNothing (publicKeyFromSeed (B.replicate 31 1)))
  check "a 33-byte seed is refused" (isNothing (publicKeyFromSeed (B.replicate 33 1)))
  let sig = fromJust (sign seed (B.pack [1]))
  check "a short public key does not verify" (not (verify (B.init pub) (B.pack [1]) sig))
  check "a short signature does not verify" (not (verify pub (B.pack [1]) (B.init sig)))

  -- The shim may be handed a NULL pointer for an empty ByteString.
  check "an empty message signs and verifies" (verify pub B.empty (fromJust (sign seed B.empty)))
  check "an empty message signs and verifies in a domain" $
    verifyInDomain pub domain B.empty (fromJust (signInDomain seed domain B.empty))

  check "an empty domain is refused" (isNothing (signInDomain seed T.empty msg))
  check "a 255-byte domain is accepted" (isJust (signInDomain seed (T.replicate 255 (T.pack "a")) msg))
  check "a 256-byte domain is refused" (isNothing (signInDomain seed (T.replicate 256 (T.pack "a")) msg))
  -- "é" is two bytes of UTF-8: 128 of them are 128 characters but 256 bytes — over the bound.
  check "the bound is in bytes, not characters (128 x e-acute = 256 bytes)" (isNothing (signInDomain seed (T.replicate 128 (T.pack "\233")) msg))
  check "the bound is in bytes, not characters (127 x e-acute = 254 bytes)" (isJust (signInDomain seed (T.replicate 127 (T.pack "\233")) msg))

  let dsig = fromJust (signInDomain seed domain msg)
      rsig = fromJust (sign seed msg)
  check "a domain signature verifies in its domain" (verifyInDomain pub domain msg dsig)
  check "a domain signature does not verify in another" (not (verifyInDomain pub (T.pack "archon/test/v2") msg dsig))
  check "a domain signature never verifies raw" (not (verify pub msg dsig))
  check "a raw signature verifies in no domain" (not (verifyInDomain pub domain msg rsig))

  let text = encodeKey pub
  check "key text round trips" (decodeKey text == Just pub)
  check "the key text prefix is exact" (isNothing (decodeKey (T.toUpper text)))
  check "key text digits may be uppercase" (decodeKey (keyTextPrefix <> T.toUpper (toHex pub)) == Just pub)

  let pem = fromJust (pubkeyToSPKIPEM pub)
  check "SPKI PEM round trips" (spkiPEMToPubkey pem == Just pub)
  -- Padding in the FIRST quad. The body's last character would prove nothing: a 44-byte SPKI
  -- already ends in "=", so replacing it with "=" leaves the PEM unchanged.
  let body = T.lines pem !! 1
      broken = T.replace body (T.take 2 body <> T.pack "=" <> T.drop 3 body) pem
  check "the corrupted PEM differs from the original" (broken /= pem)
  check "base64 padding is refused outside the final quad" (isNothing (spkiPEMToPubkey broken))

  n <- readIORef failures
  if n == 0 then putStrLn "all unit checks passed" else putStrLn (show n ++ " failed") >> exitFailure
