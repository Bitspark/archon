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

import { promptHidden, terminalIo, type HiddenPromptIo } from "../src/cmd/key_store.js";

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
