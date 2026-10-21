# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-21

### Added

- `XRayConfig` for reading and writing an Xray-core JSON configuration.
- Models for inbounds, outbounds, routing, stream settings, policy, and the API.
- Typed settings for VLESS (including adding and removing clients) and dokodemo-door.
- Package version is taken from `xray_tools.__version__` and replaced with the git tag when the distribution is built.
