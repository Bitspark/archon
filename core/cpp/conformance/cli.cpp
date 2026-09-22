// Conformance CLI (c++) — a dev/CI artifact, not part of the library surface.
//
// Implements the `conformance v1` protocol: `conformance <family>` reads the whole
// vectors/identity.json on stdin, selects its family's cases, RECOMPUTES each result from the
// case INPUTS (ignoring the expected value the oracle carries), and writes one NDJSON line per
// case to stdout in input order.
//
// The JSON reader below is deliberately small and local rather than a vendored library. It
// handles exactly what the oracle contains — objects, arrays, strings with escapes, booleans,
// numbers, null — and nothing else. A general library would be ~900 KB vendored or a
// network fetch at build time, for a dev artifact that parses one known file shape. Malformed
// input is a broken vectors file, not a case the families are testing, so it aborts loudly.

#include "archon/core.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

// --- a minimal JSON value -------------------------------------------------------------

struct Json;
using JsonPtr = std::shared_ptr<Json>;

struct Json {
  enum class Kind { Null, Bool, Number, String, Array, Object } kind = Kind::Null;
  bool boolean = false;
  double number = 0;
  std::string text;
  std::vector<JsonPtr> array;
  std::map<std::string, JsonPtr> object;

  bool has(const std::string& key) const {
    return kind == Kind::Object && object.find(key) != object.end();
  }
  const Json& at(const std::string& key) const {
    auto it = object.find(key);
    if (it == object.end()) {
      std::cerr << "conformance: vectors are missing the field \"" << key << "\"\n";
      std::exit(1);
    }
    return *it->second;
  }
};

class Parser {
 public:
  explicit Parser(const std::string& input) : s_(input) {}

  JsonPtr parse() {
    skip();
    JsonPtr v = value();
    return v;
  }

 private:
  const std::string& s_;
  std::size_t i_ = 0;

  [[noreturn]] void fail(const char* what) const {
    std::cerr << "conformance: malformed vectors JSON at offset " << i_ << ": " << what << "\n";
    std::exit(1);
  }

  void skip() {
    while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r')) {
      ++i_;
    }
  }

  bool literal(const char* word) {
    std::size_t n = std::char_traits<char>::length(word);
    if (s_.compare(i_, n, word) == 0) {
      i_ += n;
      return true;
    }
    return false;
  }

  JsonPtr value() {
    skip();
    if (i_ >= s_.size()) fail("unexpected end of input");
    char c = s_[i_];
    auto out = std::make_shared<Json>();
    if (c == '{') {
      ++i_;
      out->kind = Json::Kind::Object;
      skip();
      if (i_ < s_.size() && s_[i_] == '}') { ++i_; return out; }
      for (;;) {
        skip();
        if (i_ >= s_.size() || s_[i_] != '"') fail("expected an object key");
        std::string key = string_body();
        skip();
        if (i_ >= s_.size() || s_[i_] != ':') fail("expected ':'");
        ++i_;
        out->object[key] = value();
        skip();
        if (i_ < s_.size() && s_[i_] == ',') { ++i_; continue; }
        if (i_ < s_.size() && s_[i_] == '}') { ++i_; return out; }
        fail("expected ',' or '}'");
      }
    }
    if (c == '[') {
      ++i_;
      out->kind = Json::Kind::Array;
      skip();
      if (i_ < s_.size() && s_[i_] == ']') { ++i_; return out; }
      for (;;) {
        out->array.push_back(value());
        skip();
        if (i_ < s_.size() && s_[i_] == ',') { ++i_; continue; }
        if (i_ < s_.size() && s_[i_] == ']') { ++i_; return out; }
        fail("expected ',' or ']'");
      }
    }
    if (c == '"') {
      out->kind = Json::Kind::String;
      out->text = string_body();
      return out;
    }
    if (literal("true")) { out->kind = Json::Kind::Bool; out->boolean = true; return out; }
    if (literal("false")) { out->kind = Json::Kind::Bool; out->boolean = false; return out; }
    if (literal("null")) { out->kind = Json::Kind::Null; return out; }
    // number
    std::size_t start = i_;
    if (i_ < s_.size() && (s_[i_] == '-' || s_[i_] == '+')) ++i_;
    while (i_ < s_.size() &&
           (std::isdigit(static_cast<unsigned char>(s_[i_])) || s_[i_] == '.' || s_[i_] == 'e' ||
            s_[i_] == 'E' || s_[i_] == '-' || s_[i_] == '+')) {
      ++i_;
    }
    if (i_ == start) fail("not a JSON value");
    out->kind = Json::Kind::Number;
    out->number = std::strtod(s_.substr(start, i_ - start).c_str(), nullptr);
    return out;
  }

  /// A JSON string, unescaped. The oracle's PEM cases carry \n inside string values, so this
  /// is not optional — reading them raw would produce a PEM with a literal backslash-n.
  std::string string_body() {
    if (s_[i_] != '"') fail("expected a string");
    ++i_;
    std::string out;
    while (i_ < s_.size()) {
      char c = s_[i_++];
      if (c == '"') return out;
      if (c != '\\') { out.push_back(c); continue; }
      if (i_ >= s_.size()) fail("unterminated escape");
      char e = s_[i_++];
      switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          if (i_ + 4 > s_.size()) fail("truncated \\u escape");
          unsigned code = std::strtoul(s_.substr(i_, 4).c_str(), nullptr, 16);
          i_ += 4;
          // The oracle's non-ASCII lives in notes, which are never read as case input, so a
          // straightforward UTF-8 emission is enough here.
          if (code < 0x80) {
            out.push_back(static_cast<char>(code));
          } else if (code < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
          } else {
            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
          }
          break;
        }
        default: fail("unknown escape");
      }
    }
    fail("unterminated string");
  }
};

// --- output ---------------------------------------------------------------------------

std::string quote(const std::string& in) {
  std::string out = "\"";
  for (char c : in) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(c);
        }
    }
  }
  out.push_back('"');
  return out;
}

archon::Bytes unhex(const std::string& text) {
  archon::Bytes out;
  out.reserve(text.size() / 2);
  auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
  };
  for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>((digit(text[i]) << 4) | digit(text[i + 1])));
  }
  return out;
}

/// The oracle's two-shape result: {"ok": …} or {"error": true}.
std::string result_of(const std::optional<std::string>& value) {
  return value ? "{\"ok\":" + quote(*value) + "}" : "{\"error\":true}";
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: conformance <family>\n";
    return 2;
  }
  const std::string family = argv[1];

  std::ostringstream buffer;
  buffer << std::cin.rdbuf();
  const std::string input = buffer.str();

  Parser parser(input);
  JsonPtr doc = parser.parse();
  if (!doc->has(family)) {
    std::cerr << "conformance: no such family: " << family << "\n";
    return 1;
  }

  for (const JsonPtr& element : doc->at(family).array) {
    const Json& c = *element;
    if (!c.has("name")) continue;  // a leading note object
    std::string line = "{\"name\":" + quote(c.at("name").text);

    if (family == "pubkey_from_seed") {
      auto pub = archon::public_key_from_seed(unhex(c.at("seed").text));
      line += ",\"pubkey\":" + quote(pub ? archon::to_hex(*pub) : "");
    } else if (family == "key_encode") {
      line += ",\"text\":" + quote(archon::encode_key(unhex(c.at("pubkey").text)));
    } else if (family == "keycodec") {
      const std::string kind = c.at("kind").text;
      std::optional<std::string> out;
      if (kind == "encode_pkcs8") {
        out = archon::seed_to_pkcs8_pem(unhex(c.at("key").text));
      } else if (kind == "encode_spki") {
        out = archon::pubkey_to_spki_pem(unhex(c.at("key").text));
      } else if (kind == "decode_pkcs8") {
        auto seed = archon::pkcs8_pem_to_seed(c.at("pem").text);
        if (seed) out = archon::to_hex(*seed);
      } else if (kind == "decode_spki") {
        auto pub = archon::spki_pem_to_pubkey(c.at("pem").text);
        if (pub) out = archon::to_hex(*pub);
      } else {
        std::cerr << "unknown keycodec kind: " << kind << "\n";
        return 1;
      }
      line += ",\"result\":" + result_of(out);
    } else if (family == "signature_verify") {
      bool ok = archon::verify(unhex(c.at("pubkey").text), unhex(c.at("message").text),
                               unhex(c.at("sig").text));
      line += std::string(",\"valid\":") + (ok ? "true" : "false");
    } else if (family == "hex_decode") {
      const std::string kind = c.at("kind").text;
      const std::string text = c.at("hex").text;
      std::optional<archon::Bytes> decoded;
      if (kind == "seed") decoded = archon::seed_from_hex(text);
      else if (kind == "pubkey") decoded = archon::pubkey_from_hex(text);
      else if (kind == "signature") decoded = archon::signature_from_hex(text);
      else { std::cerr << "unknown hex_decode kind: " << kind << "\n"; return 1; }
      std::optional<std::string> out;
      if (decoded) out = archon::to_hex(*decoded);
      line += ",\"result\":" + result_of(out);
    } else if (family == "domain_sign") {
      auto sig = archon::sign_in_domain(unhex(c.at("seed").text), c.at("domain").text,
                                        unhex(c.at("message").text));
      std::optional<std::string> out;
      if (sig) out = archon::to_hex(*sig);
      line += ",\"result\":" + result_of(out);
    } else if (family == "domain_verify") {
      bool ok = archon::verify_in_domain(unhex(c.at("pubkey").text), c.at("domain").text,
                                         unhex(c.at("message").text), unhex(c.at("sig").text));
      line += std::string(",\"valid\":") + (ok ? "true" : "false");
    } else {
      std::cerr << "conformance: unhandled family: " << family << "\n";
      return 1;
    }

    line += "}";
    std::cout << line << "\n";
  }
  return 0;
}
