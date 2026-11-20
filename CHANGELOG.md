# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.3](https://github.com/Pina-i/pinai/compare/v0.4.2...v0.4.3) - 2026-11-20

### Added

- *(idp)* every instance describes the official mobile app

## [0.4.2](https://github.com/Pina-i/pinai/compare/v0.4.1...v0.4.2) - 2026-11-19

### Added

- *(idp)* devices name themselves, and can be renamed

### Fixed

- *(idp)* names people read refuse hidden and control characters

## [0.4.1](https://github.com/Pina-i/pinai/compare/v0.4.0...v0.4.1) - 2026-11-18

### Added

- *(idp)* find people by name or address to add as friends

### Fixed

- *(api)* log a peer's failure as a warning, not a server error
- *(identity)* keep a sign-up still to confirm out of others' reach
- *(identity)* refuse a domain no name server could answer
- *(federation)* screen a peer's name as it is connected to
- *(idp)* say nothing of where a refused peer address leads
- *(federation)* refuse IPv6 addresses into private space
- *(federation)* hold a signed request's screen to its deadline
- *(federation)* read a peer's answers within the body cap
- *(federation)* screen every redirect a peer answers
- *(federation)* keep only what a peer says of its own actors
- *(groups)* tell and record a group change only where its write took it
- *(identity)* read our domain with its default port as ours
- *(federation)* retry a profile its instance didn't describe within the hour
- *(presence)* bound what a peer's presence stream can hold

## [0.4.0](https://github.com/Pina-i/pinai/compare/v0.3.2...v0.4.0) - 2026-11-16

### Added

- *(e2ee)* [**breaking**] devices rejoin their conversations by themselves ([#14](https://github.com/Pina-i/pinai/pull/14))
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
