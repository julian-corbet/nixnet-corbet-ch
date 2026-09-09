Checks are selected through `.ci/ccid.toml` and run by the pinned shared ccid runner on a trusted worker.

The default selection is `native,rust,package`. Native Linux success does not certify a foreign architecture, a separately selected image or hardware gate, or publication. Use `list` to inspect available native Nix checks, and select existing results or affected checks before scheduling more work.

Additional coverage limits:

- Retain rustfmt/clippy/test plus package build alongside Nix module/VM checks.

Hosted Actions keeps the full portable workflow available for manual fallback.
