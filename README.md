# Modular password-based encryption for Rust

[![Travis Build Status](https://img.shields.io/travis/com/exonum/pwbox-rs/master.svg?label=Linux%20Build)](https://travis-ci.com/exonum/pwbox-rs) 
[![License: Apache-2.0](https://img.shields.io/github/license/exonum/pwbox-rs.svg)](https://github.com/exonum/pwbox-rs/blob/master/LICENSE)
![rust 1.34.0+ required](https://img.shields.io/badge/rust-1.34.0+-blue.svg?label=Required%20Rust)

**Documentation:** [![crate docs (master)](https://img.shields.io/badge/master-yellow.svg?label=docs)](https://exonum.github.io/pwbox-rs/pwbox/)

`pwbox` crate provides utilities for password-based encryption together with
corresponding composable cryptographic primitives. Using the crate, it is
possible to securely encrypt sensitive data with a password, serialize it
to any `serde`-supported format, and restore data.

**Warning.** Although `pwbox` is constructed analogously to an Ethereum keystore
(and is compatible with it, see crate docs), no independent cryptology expertise has been conducted
regarding its safety. Use at your own risk.

## Usage

See crate documentation for more details how to use the crate.

## License

`pwbox` is licensed under the Apache License (Version 2.0). See [LICENSE](LICENSE) for details.
