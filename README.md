# avcscope


---

A **read-only** terminal UI (Rust + [ratatui](https://ratatui.rs)) for triaging
SELinux AVC denials. It parses denials, de-duplicates them, shows the live
enforcing mode, and — crucially — nudges you toward the *root cause* (mislabel,
boolean, port) instead of handing you an `audit2allow` to blindly apply.

It **cannot** change anything: no `setenforce`, `setsebool`, `semanage`,
`semodule`, or `restorecon`. It only reads logs and (optionally) runs read-only
query commands. Remediations are shown as text for you to review and run.

![Main](https://github.com/koepnick/avcscope/blob/main/example/main.png)

![Detail](https://github.com/koepnick/avcscope/blob/main/example/detail.png)

![Demo Data](https://github.com/koepnick/avcscope/blob/main/example/demo.png)

## Note
> This tool was created for my own convenience. I will likely add features as 
> I need them but do not intend to expand the root scope.
>
> Suggestions are welcome.

## Build & run

```sh

# TLDR
make
sudo make install
```

— or —
```sh

# Static (recommended)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
./target/x86_64-unkonwn-linux-musl/release/avcscope --demo

# With live data

## STDIN
sudo ausearch -m AVC,USER_AVC,SELINUX_ERR -ts today | avcscope

## Target log file
avcscope --file /var/log/audit/audit.log

## Best guess
avcscope          # auto: ausearch -> audit.log -> demo
```

— or —

```sh

# Basic
cargo build --release
./target/release/avcscope --demo
```


> **Toolchain note:** `Cargo.lock` pins `instability`/`darling` to versions that
> build on older rustc (tested on **rustc 1.75**, Ubuntu 24.04). On a recent
> toolchain you can delete `Cargo.lock` and let cargo resolve freely.

## Keybindings (vim)

| key | action |
|-----|--------|
| `j` / `k` | move down / up |
| `g` / `G` | jump to top / bottom |
| `Ctrl-d` / `Ctrl-u` | half page (scrolls the detail pane when open) |
| `l` / `Enter` | open detail for the selected denial |
| `h` / `Esc` | back out of detail / clear active filter |
| `/` | incremental search (Enter keeps the filter, Esc clears) |
| `s` | cycle sort: count → recent → src-type |
| `r` | reload from the source |
| `:` | command line — `:q` `:sort` `:reload` `:help` |
| `?` | toggle help overlay |
| `q` | quit (or close the detail pane) |

## What you see

- **Status badge** — `ENFORCING` (red) / `PERMISSIVE` (amber) / `DISABLED`
  (grey), read from `/sys/fs/selinux/enforce`, refreshed every 2s.
- **Running totals** — `N unique / M total`. The list shows one row per
  *distinct* denial with an `×N` group count.
- **Detail pane** — full subject/target context breakdown, distinct paths &
  pids in the group, first/last seen, and read-only diagnosis hints.

## De-duplication

Denials are grouped by `(outcome, perms, scontext, tcontext, tclass, comm)`.
pid, timestamp, inode and the specific path are deliberately *excluded* from the
key — "`httpd_t` denied `read` on `user_home_t`" is one problem whether it hit 1
file or 500. The distinct paths and pids are still preserved inside the group
and shown in the detail pane.

## Tests

```sh
cargo test
```

Covers field parsing, MLS levels containing colons, de-duplication, the running
total, and path preservation.

Note: These tests were generated via an LLM. Full coverage is not guaranteed.
