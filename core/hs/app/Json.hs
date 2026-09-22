-- | Just enough JSON to read the oracle. Not a general-purpose parser, and deliberately not
-- aeson: archon-core and its conformance CLI depend on GHC boot packages only, so building
-- either needs nothing from Hackage — and nothing whose support for a new GHC lags the release.
module Json
  ( Json (..)
  , parse
  , field
  , stringField
  , quote
  ) where

import Data.Char (chr, isDigit, isHexDigit, isSpace, ord)
import Numeric (readHex, showHex)

data Json
  = JObject [(String, Json)]
  | JArray [Json]
  | JString String
  | JNumber Double
  | JBool Bool
  | JNull
  deriving (Show)

parse :: String -> Either String Json
parse input = case value (skip input) of
  Right (v, rest) | all isSpace rest -> Right v
  Right _ -> Left "trailing input after the document"
  Left e -> Left e

field :: String -> Json -> Maybe Json
field key (JObject kvs) = lookup key kvs
field _ _ = Nothing

stringField :: String -> Json -> Maybe String
stringField key j = case field key j of
  Just (JString s) -> Just s
  _ -> Nothing

type P a = String -> Either String (a, String)

skip :: String -> String
skip = dropWhile isSpace

value :: P Json
value ('{' : rest) = object (skip rest) []
value ('[' : rest) = array (skip rest) []
value ('"' : rest) = do
  (s, r) <- string rest
  pure (JString s, r)
value ('t' : 'r' : 'u' : 'e' : rest) = Right (JBool True, rest)
value ('f' : 'a' : 'l' : 's' : 'e' : rest) = Right (JBool False, rest)
value ('n' : 'u' : 'l' : 'l' : rest) = Right (JNull, rest)
value s@(c : _) | c == '-' || isDigit c = number s
value s = Left ("unexpected input: " ++ take 20 s)

object :: String -> [(String, Json)] -> Either String (Json, String)
object ('}' : rest) acc = Right (JObject (reverse acc), rest)
object ('"' : rest) acc = do
  (key, r1) <- string rest
  r2 <- case skip r1 of
    ':' : r -> Right (skip r)
    _ -> Left "expected ':'"
  (v, r3) <- value r2
  case skip r3 of
    ',' : r -> object (skip r) ((key, v) : acc)
    '}' : r -> Right (JObject (reverse ((key, v) : acc)), r)
    _ -> Left "expected ',' or '}'"
object s _ = Left ("bad object at: " ++ take 20 s)

array :: String -> [Json] -> Either String (Json, String)
array (']' : rest) acc = Right (JArray (reverse acc), rest)
array s acc = do
  (v, r1) <- value s
  case skip r1 of
    ',' : r -> array (skip r) (v : acc)
    ']' : r -> Right (JArray (reverse (v : acc)), r)
    _ -> Left "expected ',' or ']'"

number :: P Json
number s =
  let (digits, rest) = span (\c -> isDigit c || c `elem` "+-.eE") s
   in case reads digits of
        [(d, "")] -> Right (JNumber d, rest)
        _ -> Right (JNumber 0, rest) -- the oracle carries no numbers anything reads

-- | A string body after its opening quote, with escapes resolved — including \uXXXX surrogate
-- pairs, since the oracle's notes are free text and a CLI that choked on one would fail a case
-- it was never asked about.
string :: P String
string = go []
  where
    go acc ('"' : rest) = Right (reverse acc, rest)
    go acc ('\\' : c : rest) = case c of
      '"' -> go ('"' : acc) rest
      '\\' -> go ('\\' : acc) rest
      '/' -> go ('/' : acc) rest
      'b' -> go ('\b' : acc) rest
      'f' -> go ('\f' : acc) rest
      'n' -> go ('\n' : acc) rest
      'r' -> go ('\r' : acc) rest
      't' -> go ('\t' : acc) rest
      'u' -> do
        (hi, r1) <- hex4 rest
        if hi >= 0xD800 && hi <= 0xDBFF
          then case r1 of
            '\\' : 'u' : r2 -> do
              (lo, r3) <- hex4 r2
              go (chr (0x10000 + (hi - 0xD800) * 0x400 + (lo - 0xDC00)) : acc) r3
            _ -> Left "unpaired surrogate"
          else go (chr hi : acc) r1
      _ -> Left "unknown escape"
    go acc (c : rest) = go (c : acc) rest
    go _ [] = Left "unterminated string"
    hex4 s = case splitAt 4 s of
      (h, r) | length h == 4, all isHexDigit h, [(n, "")] <- readHex h -> Right (n, r)
      _ -> Left "bad \\u escape"

-- | A JSON string literal. Control characters are escaped; everything else passes through, as
-- the harness reads UTF-8.
quote :: String -> String
quote s = '"' : concatMap esc s ++ "\""
  where
    esc '"' = "\\\""
    esc '\\' = "\\\\"
    esc '\n' = "\\n"
    esc '\r' = "\\r"
    esc '\t' = "\\t"
    esc c
      | ord c < 0x20 = "\\u" ++ replicate (4 - length h) '0' ++ h
      | otherwise = [c]
      where
        h = showHex (ord c) ""
