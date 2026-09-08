# Changelog

All notable changes to this project are documented here.

## NIDS v2.0.0

### Added

- Time-windowed SYN scan detection
- Unique destination-port scan detection
- Alert cooldown and duplicate suppression
- Structured alert severity levels
- Detection event types
- JSONL alert logging
- External TOML configuration
- Configuration validation
- Invalid-interface handling
- Permission and Scapy error handling
- Quiet monitoring mode
- Command-line argument support
- Modular detector package
- Dedicated logging module
- Automated pytest test suite
- GitHub Actions continuous integration

### Changed

- Refactored the original single-file NIDS architecture
- Improved SYN detection to avoid indefinite packet accumulation
- Improved alert messages with detection evidence
- Separated configuration, detection, and logging responsibilities

### Tested

- Suspicious TCP port detection
- High-volume SYN detection
- Unique-port scan detection
- Detection time-window expiration
- Alert deduplication
- Below-threshold traffic
- JSON alert generation
- CLI behavior
- Configuration validation
