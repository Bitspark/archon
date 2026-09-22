-- | archon's identity floor, in Haskell.
--
-- Two questions and nothing else: are these bytes that key, and is this signature that key's.
-- Custody, authority and trust are deliberately elsewhere.
--
-- Held to the same oracle as every other core — @vectors/identity.json@, 105 cases, including
-- the 36 ADR 0008 verification-profile classes where Ed25519 libraries disagree by default.
module Archon.Core
  ( module Archon.Core.Crypto
  , module Archon.Core.HexBytes
  , module Archon.Core.KeyText
  , module Archon.Core.KeyCodec
  ) where

import Archon.Core.Crypto
import Archon.Core.HexBytes
import Archon.Core.KeyCodec
import Archon.Core.KeyText
