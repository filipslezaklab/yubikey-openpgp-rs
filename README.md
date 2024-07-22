# (POC) Working with OpenPGP smart cards via rust

## Why

There are no crates that provides a way to handle yubikey OpenPGP module programmatically via rust programming language. And making a wrapper around programs like ykman or gpg, especially gpg, is at best not ideal.

## Goal

Make sure it's possible to:

- Reset
- Generate keys (DEC, AUTH, SIG)
- Add info about user

Onto Yubikey 4/5 OpenPGP module.

## Special thanks

This would not be possible if not for [openpgp-card-tools](https://codeberg.org/openpgp-card/openpgp-card-tools), it served well as a guide on how to
deal with [openpgp-card](https://docs.rs/crate/openpgp-card/0.5.0) crate.
