-- | What an outside consumer of bitspark-archon-core must be able to do.
--
-- This builds against archon as a DEPENDENCY, resolved by Cabal, not as source in the same tree.
-- Passing the oracle proves the code; it says nothing about whether the package is right — a
-- c-source missing from the package description, an include directory that is not exported, or
-- a pkg-config dependency the consumer is not told about all pass conformance and fail here.
--
-- Two claims, the same two every archon consumer asserts in every language:
--   1. domain separation holds, in every direction;
--   2. the ADR 0008 profile is enforced, on the pair that is load-bearing in EVERY language —
--      profile-mixed-order-A-k-divisible and profile-identity-R, oracle bytes verbatim. Every
--      implementation measured before 0008 accepted both, so nothing but archon's own check can
--      refuse them. For Haskell that check is libsodium's; OpenSSL alone would accept both.
module Main (main) where

import Archon.Core
import Control.Monad (unless)
import qualified Data.ByteString as B
import Data.Maybe (fromJust)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

check :: Bool -> String -> IO ()
check ok what = unless ok $ hPutStrLn stderr ("consumer assertion failed: " ++ what) >> exitFailure

bytes :: String -> B.ByteString
bytes = fromJust . fixed
  where
    fixed h = B.pack <$> mapM (\i -> readByte (take 2 (drop (2 * i) h))) [0 .. length h `div` 2 - 1]
    readByte [a, b] = (\x y -> fromIntegral (x * 16 + y)) <$> digit a <*> digit b
    readByte _ = Nothing
    digit c = lookup c (zip "0123456789abcdef" [0 :: Int ..])

main :: IO ()
main = do
  check librariesMeetFloors "the loaded OpenSSL and libsodium must meet archon's floors"

  let seed = B.pack [0 .. 31]
      domain = T.pack "archon/test/v1"
      message = B.pack (map (fromIntegral . fromEnum) "hello")
      pub = fromJust (publicKeyFromSeed seed)

  let signature = fromJust (signInDomain seed domain message)
  check (verifyInDomain pub domain message signature) "a domain signature must verify in its own domain"
  check (not (verifyInDomain pub (T.pack "archon/test/v2") message signature)) "a domain signature must not verify in another domain"
  check (not (verify pub message signature)) "a domain signature must never verify as a raw signature"

  let raw = fromJust (sign seed message)
  check (verify pub message raw) "a raw signature must verify raw"
  check (not (verifyInDomain pub domain message raw)) "a raw signature must not verify in any domain"

  -- ADR 0008 class 4: A = A_good + T8, order 8L, with k divisible by 8 so BOTH equations hold.
  let mixedOrderA = bytes "05edb8c261651304ea335a4397e0696b9fb37c99aa8023ee1583a2f3e43d9fe4"
      mixedOrderMessage = bytes "6d697865642d6f72646572233133"
      mixedOrderSig =
        bytes
          ( "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1"
              ++ "20e561d759891b93dd85ac31f464fc01adb9d3d89074eaa7795084f43661a90b"
          )
  check (not (verify mixedOrderA mixedOrderMessage mixedOrderSig)) "a mixed-order public key must be refused, though both equations hold"
  check (not (verifyInDomain mixedOrderA domain mixedOrderMessage mixedOrderSig)) "a mixed-order public key must be refused in a domain too"

  -- ADR 0008 class 5: R is the identity point and S = k*a, so the equation holds under every
  -- formulation. RFC 8032 pure verification accepts it; no honest signer produces it.
  let honestA = bytes "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
      identityRSig =
        bytes
          ( "0100000000000000000000000000000000000000000000000000000000000000"
              ++ "04201a21f9221727c221b35265ca6248968a426e9fb5168e368d7dcdaa05fa07"
          )
  check (not (verify honestA message identityRSig)) "an identity R must be refused, though RFC 8032 pure verification accepts it"

  let text = encodeKey pub
  check (decodeKey text == Just pub) "the canonical key text must round trip"
  check ((pubkeyToSPKIPEM pub >>= spkiPEMToPubkey) == Just pub) "SPKI PEM must round trip"

  TIO.putStrLn (T.pack "consumer ok: " <> text)
