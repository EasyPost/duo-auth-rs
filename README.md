This is a small program which implements Duo authentication with a notion of whitelisted IPs
and recent IPs.

It's designed to be called using `pam_exec(2)` to provide better 2fa for certain services.

![CI](https://github.com/EasyPost/duo-auth-rs/workflows/CI/badge.svg?branch=master)

Note that it does not currently support prompting for the device to use and will always send a push to the user's
primary device. There's no way to enter a pin code (because there's no way to prompt for input conditionally and
it's a huge pain in the butt to get prompted for a password on every login).

Configuration should follow the format described in `example_config.json`; the default is looked for at
`/etc/duo-auth-rs.json`.

This software is licensed under the ISC license, a copy of which can be found in the file [LICENSE.txt](LICENSE.txt).

This tool requires Rust 1.33 or later.
