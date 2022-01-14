0.2.3
-----
- Update various dependencies
- Change edition from 2018 to 2021 (requires Rust 1.56.0 or later)

0.2.2
-----
- Update rusqlite to 0.24 for RUSTSEC-2020-0014
- Update to reqwest 0.10
- Replace `error-chain` with `thiserror`

0.2.1
-----
- Update rusqlite to 0.16 (bumps statically-linked sqlite to 3.24)

0.2.0
-----
- Update to Rust 2018 edition (requires Rust 1.31 or later)
- Fix bugs in IpWhitelist subnet masking for IPv6
- Lots of internal changes and dependency bumps

0.1.5
-----
- Bump rusqlite dependency
- Use `$CARGO_PKG_VERSION` to populate user-agent and --help version numbers (thank you for the suggestion, @simlay)

0.1.4
-----
- Bump some requirements
- Actually parse result JSON

0.1.3
-----
- add `mask_ipv6` config option, which causes all IPv6 addresses to be treated as the nearest /64 for purposes of recent IP

0.1.2
----
- Disable printing to stderr because OpenSSH never pushes `pam_info` messages until an after-login banner anyway
- Hide debug logs from reqwest/hyper

0.1.1
-----
- Print to stderr before pushing to duo

0.1.0
-----
- Initial release
