import argparse
import sys
import warnings

from fastapi_fullauth.utils import generate_secret_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fullauth",
        description="fastapi-fullauth command-line utilities.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("secret", help="Print a random SECRET_KEY suitable for FULLAUTH_SECRET_KEY.")
    sub.add_parser(
        "check",
        help="Load FULLAUTH_* config from the environment / .env, print the resolved "
        "settings, and report any warnings before you boot the app.",
    )

    args = parser.parse_args(argv)

    if args.command == "secret":
        print(generate_secret_key())
        return 0

    if args.command == "check":
        return _check()

    return 1


def _check() -> int:
    """Resolve FullAuthConfig from the environment and report the effective state.

    Returns 1 if the config fails to construct (so it's usable as a CI gate),
    otherwise 0 even when warnings are present (warnings are advisory)."""
    from fastapi_fullauth.config import FullAuthConfig
    from fastapi_fullauth.fullauth import FullAuth

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            config = FullAuthConfig()
        except Exception as exc:  # pydantic ValidationError / ValueError from validators
            print("Config error: could not construct FullAuthConfig from the environment.\n")
            print(exc)
            return 1
        # Surface the same multi-worker warning init would emit, without booting an app.
        FullAuth._warn_memory_backends(config)

    messages = [str(w.message) for w in caught]
    secret_generated = any("FULLAUTH_SECRET_KEY is not set" in m for m in messages)
    _print_config(config, secret_generated=secret_generated)

    if messages:
        print("\nWarnings:")
        for message in messages:
            print(f"  - {message}")
        print(f"\n{len(messages)} warning(s). Config is usable but review the above.")
    else:
        print("\nNo warnings. Config looks good.")
    return 0


def _print_config(config: "object", *, secret_generated: bool) -> None:
    from fastapi_fullauth.config import FullAuthConfig

    assert isinstance(config, FullAuthConfig)

    def feature(enabled: bool, backend: str) -> str:
        return backend if enabled else "off"

    rows = [
        ("backend (default)", config.BACKEND),
        ("redis url", "set" if config.REDIS_URL else "not set"),
        ("secret key", "generated (set FULLAUTH_SECRET_KEY)" if secret_generated else "set"),
        ("algorithm", config.ALGORITHM),
        ("access token expiry", f"{config.ACCESS_TOKEN_EXPIRE_MINUTES} min"),
        ("refresh token expiry", f"{config.REFRESH_TOKEN_EXPIRE_DAYS} days"),
        ("blacklist", feature(config.BLACKLIST_ENABLED, config.BLACKLIST_BACKEND)),
        ("lockout", feature(config.LOCKOUT_ENABLED, config.LOCKOUT_BACKEND)),
        ("rate limit", feature(config.AUTH_RATE_LIMIT_ENABLED, config.RATE_LIMIT_BACKEND)),
        ("passkeys", config.PASSKEY_CHALLENGE_BACKEND if config.PASSKEY_ENABLED else "off"),
        ("api prefix", config.API_PREFIX.rstrip("/") + config.AUTH_ROUTER_PREFIX),
    ]
    if config.PASSKEY_ENABLED:
        rows.append(("passkey rp id", config.PASSKEY_RP_ID or "(unset)"))

    width = max(len(label) for label, _ in rows)
    print("Effective configuration:")
    for label, value in rows:
        print(f"  {label.ljust(width)}  {value}")
    print("\nOAuth providers and token transports are configured in code, not env.")


if __name__ == "__main__":
    sys.exit(main())
