# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 0.5.0 - 2021-09-20

- Update dependencies and bump MSRV up to 1.55.

## 0.4.0 - 2021-01-05

### Changed

- Make non-instantiated types (such as cryptosuites) to structs.
- Use a separate error type, `MacMismatch`, instead of `()` in `Cipher::open()`.
- Update dependencies.

## 0.3.0 - 2020-03-11

### Added

- Support `no_std` environment.

### Changed

- Switch error handling library from `failure` to `anyhow`.

## 0.2.1 - 2019-09-06

### Changed

- Update `sodiumoxide` dependency.

## 0.2.0 - 2019-08-06

### Added

- Extend key generation example, allowing to encrypt / decrypt any data.

### Changed

- Use newer Rust idioms.
- Update `rand` dependency.

## 0.1.4 - 2019-04-17

### Added

- Add new crate usage example that generates encryption of an Ed25519 keypair.

### Changed

- Switch to Rust 2018 edition.

## 0.1.3 - 2019-03-14

### Changed

- Update `sodiumoxide` dependency.

## 0.1.2 - 2019-01-28

### Changed

- Update crate dependencies.

## 0.1.1 - 2019-01-03

### Changed

- Use newer `failure` crate (v0.1.3 -> v0.1.5).

## 0.1.0 - 2018-12-04

The initial release of `pwbox`. 
