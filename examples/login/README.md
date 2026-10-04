# Login, end to end

A service, a key-less client and a person, logging in with archon's **published** packages
and nothing from this repository. It shows the whole exchange of [the login scheme](../../docs/login.md)
and the one decision archon leaves to the service: whether to admit.

```console
$ npm ci
$ node run.mjs
```

`run.mjs` performs two logins and checks every step, exiting 1 if any step differs from what
it prints as expected. CI runs it on every push, installing from registry.npmjs.org at
exactly the versions below.

## The three parties

| file | who | what it uses |
|---|---|---|
| [`service.mjs`](service.mjs) | the service | `@bitspark/archon-server`: the login handler, mounted on `node:http`, with an `admit` callback |
| [`client.mjs`](client.mjs) | the key-less client, e.g. a web page | `@bitspark/archon-sdk`: `proveCollect` to collect the answer, `verifyLogin` to check it; plain `fetch` otherwise, so it runs unchanged in a browser |
| `archon` | the person | `@bitspark/archon-cli`: `keygen`, then `login <url> --key-file … --authority-file …` |

The client makes its own key and never sees the person's. The person's command shows what it
is about to sign — the service, the client's key, every scope entry and the duration — and
signs only that. In `run.mjs`, `--yes` stands in for the person typing `y`.

## The authority hook

The handler calls `admit(browser, principal, authority)` only after the person's possession
proof has verified. archon interprets none of the three. Returning admits; throwing refuses
the login with `403 invalid_grant`. Nothing is stored, so the client's collect stays at
`202 authorization_pending` until the login expires.

Here the law is a toy: a map of which person is in which team, and the authority payload
names the team. In a real service it is your account store, or a grant layer such as
thesmos.

This `admit` only validates (and logs), which is the first of the three things
[login.md §4](../../docs/login.md#4-transport) asks of a law. The hook is not exactly-once: a
refused answer's law did run, and a process can stop after the law returns but before the
answer is stored. So a law with effects must either key them by the browser key it is
handed, or leave them until the client has collected.

**What `admit` receives as `authority`:** the exact bytes of the JSON value the person's
command sent. `archon login --authority-file <file>` sends the file's bytes as a
lowercase-hex JSON string, so a file holding `projects` arrives as
`"70726f6a65637473"`, quotes included. `authorityText` in [`service.mjs`](service.mjs)
decodes it. With no `--authority-file`, it is the empty string, `""`.

## Tested versions

| package | version |
|---|---|
| `@bitspark/archon` | 0.8.1 |
| `@bitspark/archon-sdk` | 0.8.1 |
| `@bitspark/archon-server` | 0.8.1 |
| `@bitspark/archon-cli` | 0.8.1 |

The versions are pinned exactly in [`package.json`](package.json), and everything else is
pinned by [`package-lock.json`](package-lock.json). Which languages carry which tier, and
what each registry holds, is in [docs/languages.md](../../docs/languages.md). The same
handler exists in Go (`server/go`) and Rust (`server/rs`). Python and Java carry possession
and the envelope, but not the login scheme.

If your npm configuration routes the `@bitspark` scope to another registry (GitHub Packages,
say), install from npmjs explicitly:

```console
$ npm ci --@bitspark:registry=https://registry.npmjs.org/
```

## What this does not show

- **Keeping the person's key.** A person would store it with `archon key add` and log in with
  `login --key <name>`, which asks for the store's password; see [the key store](../../docs/keystore.md).
- **The offers form**, in which the person starts the login and the page finishes it:
  `archon login --audience …` ([login.md §4.1](../../docs/login.md)).
- **A real law.** No grant layer can yet sign through archon's store without receiving the
  seed. That is the proposal in [#47](https://github.com/Bitspark/archon/issues/47), and an
  example linking one will follow if it lands.
