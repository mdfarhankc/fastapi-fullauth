import argparse
import sys

from fastapi_fullauth.utils import generate_secret_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fullauth",
        description="fastapi-fullauth command-line utilities.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("secret", help="Print a random SECRET_KEY suitable for FULLAUTH_SECRET_KEY.")

    args = parser.parse_args(argv)

    if args.command == "secret":
        print(generate_secret_key())
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
