This is a small program which implements Duo authentication with a notion of whitelisted IPs
and recent IPs.

It's designed to be called using `pam_exec(2)` to provide better 2fa for certain services.

Note that it does not currently support prompting for the authentication mechanism to use.
