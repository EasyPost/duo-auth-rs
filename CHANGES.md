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
