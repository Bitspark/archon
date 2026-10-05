// The store's interactive prompt path, exercised under ESM with no TTY.
//
// This file exists because promptHidden reached for a bare `require("node:fs")` inside an
// ESM package (lane A's, found while wiring `login --key`): the first interactive password
// prompt would have thrown ReferenceError before reading a byte, and nothing ran the path to
// notice. The prompt's terminal is now injectable, so the same code that runs against a real
// terminal runs here against a scripted one — and a regression of that kind fails a test
// instead of the first person to type a password.
import { strict as assert } from "node:assert";
import test from "node:test";

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  legacyPromptDecoding,
  openEntered,
  promptHidden,
  readNamedKey,
  sealAndWrite,
  terminalIo,
  type HiddenPromptIo,
} from "../src/cmd/key_store.js";
import * as keystore from "../src/keystore.js";

interface Scripted extends HiddenPromptIo {
  raw: boolean[];
  written: string[];
}

function scripted(bytes: number[]): Scripted {
  const queue = [...bytes];
  const io: Scripted = {
    raw: [],
    written: [],
    setRawMode(r) {
      io.raw.push(r);
    },
    readByte() {
      return queue.length === 0 ? -1 : (queue.shift() as number);
    },
    write(t) {
      io.written.push(t);
    },
  };
  return io;
}

const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0));

test("the hidden prompt reads a line without echoing it", () => {
  const io = scripted(ascii("s3cret\n"));
  assert.equal(promptHidden("password: ", io), "s3cret");
  assert.deepEqual(io.raw, [true, false], "raw mode is set for the read and restored after it");
  assert.deepEqual(io.written, ["password: ", "\n"], "nothing typed is echoed");
});

test("the hidden prompt honours backspace and stops at EOF", () => {
  assert.equal(promptHidden("", scripted([...ascii("abcd"), 0x7f, 0x08, ...ascii("x")])), "abx");
  assert.equal(promptHidden("", scripted(ascii("no newline"))), "no newline");
  assert.equal(promptHidden("", scripted([])), "");
});

test("the hidden prompt treats ^C as an interruption and restores the terminal", () => {
  const io = scripted([...ascii("ab"), 0x03]);
  assert.throws(() => promptHidden("password: ", io), /interrupted/);
  assert.deepEqual(io.raw, [true, false], "raw mode is restored even on interruption");
});

// The real terminal's byte reader — the one place this file touches fd 0, and the closure
// the bare `require` would have to live in now — with the fd read injected, so the exact
// code that runs against a terminal runs here under ESM.
test("the terminal's byte reader runs under ESM", () => {
  const io = terminalIo((into) => {
    into[0] = 0x41;
    return 1;
  });
  assert.equal(io.readByte(), 0x41);
  assert.equal(terminalIo(() => 0).readByte(), -1, "a zero-length read is end of input");
  assert.equal(
    terminalIo(() => {
      throw new Error("EBADF");
    }).readByte(),
    -1,
    "an unreadable descriptor is end of input, not a crash",
  );
});

// ---- the prompt reads characters, not bytes (0.11.0) -------------------------------------
//
// Before 0.11.0 the prompt turned each byte into its own character, so "é" (C3 A9) became
// "Ã©" and a non-ASCII password derived a key the Go and Rust prompts never derive.

const utf8 = (s: string): number[] => [...new TextEncoder().encode(s)];

test("the hidden prompt decodes what is typed as UTF-8", () => {
  assert.equal(promptHidden("", scripted(utf8("pässwörd €5\n"))), "pässwörd €5");
});

test("backspace at the hidden prompt erases a whole character", () => {
  assert.equal(promptHidden("", scripted([...utf8("aé"), 0x7f])), "a");
  assert.equal(promptHidden("", scripted([...utf8("a€"), 0x7f, ...ascii("b")])), "ab");
});

test("the hidden prompt refuses bytes that are not UTF-8", () => {
  const io = scripted([0x61, 0xff, 0x0a]);
  assert.throws(() => promptHidden("", io), /not valid UTF-8/);
  assert.deepEqual(io.raw, [true, false], "the terminal is restored first");
});

test("the old reading of a password is each of its bytes as a character", () => {
  assert.equal(legacyPromptDecoding("é"), "Ã©");
  assert.equal(legacyPromptDecoding("plain ascii"), undefined, "ASCII reads the same both ways");
});

test("a key sealed under the old reading opens, and is re-sealed under the password as typed", () => {
  const home = mkdtempSync(join(tmpdir(), "archon-prompt-"));
  const saved = process.env["ARCHON_HOME"];
  process.env["ARCHON_HOME"] = home;
  try {
    const seed = new Uint8Array(32).fill(7);
    const typed = "pässwörd";
    const old = legacyPromptDecoding(typed) as string;
    sealAndWrite(join(home, "keys", "legacy"), seed, old, keystore.unrestricted()); // what the old prompt sealed

    // Not prompted (a password file, the environment): no fallback, the plain failure.
    assert.throws(() => openEntered("legacy", readNamedKey("legacy").file, { password: typed, prompted: false }));
    // A wrong password typed at the prompt stays wrong, and nothing is rewritten.
    const before = readNamedKey("legacy").file;
    assert.throws(() => openEntered("legacy", before, { password: "wröng", prompted: true }));
    assert.deepEqual(readNamedKey("legacy").file, before);

    // The right password typed at the prompt opens it, and re-seals it.
    const opened = openEntered("legacy", readNamedKey("legacy").file, { password: typed, prompted: true });
    assert.deepEqual(opened, seed);
    const resealed = readNamedKey("legacy").file;
    assert.deepEqual(keystore.open(resealed, typed), seed, "the password as typed now opens it");
    assert.throws(() => keystore.open(resealed, old), "the old reading no longer does");
  } finally {
    if (saved === undefined) delete process.env["ARCHON_HOME"];
    else process.env["ARCHON_HOME"] = saved;
    rmSync(home, { recursive: true, force: true });
  }
});
