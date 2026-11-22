# Fuzz seeds

Inputs the fuzz target starts from, committed on purpose. Pass the directory as a read-only corpus
after the target's own scratch corpus:

```sh
cargo +nightly fuzz run interfaces_decode fuzz/corpus/interfaces_decode fuzz/seeds/interfaces_decode
```

| Target | Seeds | What they are |
|---|---|---|
| `interfaces_decode` | `interfaces_decode/` | an empty 8-byte list, a 44-byte list of three interfaces, and a 32-byte list whose two ids descend, which the decoder refuses |
