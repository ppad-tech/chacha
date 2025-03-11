# chacha

[![](https://img.shields.io/hackage/v/ppad-chacha?color=blue)](https://hackage.haskell.org/package/ppad-chacha)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-chacha-lightblue)](https://docs.ppad.tech/chacha)

A pure Haskell implementation of the ChaCha20 stream cipher as specified
by [RFC8439][8439].

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  >
  > -- import qualified
  > import qualified Crypto.Cipher.ChaCha20 as ChaCha20
  >
  > -- encrypt some plaintext using a secret key and nonce
  > let key = "don't tell anyone my secret key!"
  > let non = "or my nonce!"
  > let ciphertext = ChaCha20.cipher key 1 non "but you can share the plaintext"
  > ciphertext
  "\192*c\248A\204\211n\130y8\197\146k\245\178Y\197=\180_\223\138\146:^\206\&0\v[\201"
  >
  > -- use the cipher with the same key, counter, and nonce to decrypt the ciphertext
  > ChaCha20.cipher key 1 non ciphertext
  "but you can share the plaintext"
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/chacha][hadoc].

## Performance

The aim is best-in-class performance for pure, highly-auditable Haskell
code.

Current benchmark figures on the simple "sunscreen input" from RFC8439
on my mid-2020 MacBook Air look like (use `cabal bench` to run the
benchmark suite):

```
  benchmarking ppad-chacha/cipher
  time                 1.554 μs   (1.510 μs .. 1.596 μs)
                       0.995 R²   (0.994 R² .. 0.997 R²)
  mean                 1.541 μs   (1.511 μs .. 1.579 μs)
  std dev              115.1 ns   (95.95 ns .. 139.7 ns)
  variance introduced by outliers: 81% (severely inflated)
```

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be [challenging to achieve][const].

The ChaCha20 cipher within passes all test vectors from RFC8439,
and the downstream AEAD-ChaCha20-Poly1305 implementation in
[ppad-aead](https://github.com/ppad-tech/aead) passes all the [Project
Wycheproof vectors][wyche].


If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal repl ppad-chacha
```

to get a REPL for the main library.

[8439]: https://datatracker.ietf.org/doc/html/rfc8439
[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/chacha
[const]: https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html
[wyche]: https://github.com/C2SP/wycheproof
