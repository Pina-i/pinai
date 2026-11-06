# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.3](https://github.com/Pina-i/pinai/compare/v0.3.2...v0.3.3) - 2026-11-06

### Added

- *(idp)* approved devices and a shared history passphrase ([#10](https://github.com/Pina-i/pinai/pull/10))

## [0.3.2](https://github.com/Pina-i/pinai/compare/v0.3.1...v0.3.2) - 2026-11-02

### Fixed

- *(federation)* signed requests get through nginx over HTTP/2

## [0.3.1](https://github.com/Pina-i/pinai/compare/v0.3.0...v0.3.1) - 2026-11-01

### Added

- *(idp)* hand the instance's Klipy key to its clients in NodeInfo

### Fixed

- *(idp)* bring a KeyPackage expiry within the lifetime instead of refusing it

## [0.3.0](https://github.com/Pina-i/pinai/compare/v0.2.0...v0.3.0) - 2026-10-31

### Added

- *(idp)* name the first admin with ADMIN_NAME

### Fixed

- *(idp)* keep the email on the login form after a refusal
