# Contributing

Thanks for your interest in contributing to FastAPI FullAuth!

## Development setup

```bash
git clone https://github.com/mdfarhankc/fastapi-fullauth.git
cd fastapi-fullauth
uv sync --dev --extra sqlalchemy --extra sqlmodel --extra redis --extra oauth
```

## Running tests

```bash
uv run pytest tests/ -v
```

## Linting and formatting

```bash
uv run ruff check .
uv run ruff format .
```

Both must pass before submitting a PR. CI enforces this.

## Making changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Add tests for new functionality
4. Ensure all tests pass and lint is clean
5. Submit a pull request

## Branch naming

| Prefix | Use |
|--------|-----|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `refactor/` | Code improvements |
| `docs/` | Documentation |

## What to contribute

- Bug fixes
- New OAuth providers (Apple, Discord, Microsoft, etc.)
- Adapter implementations (MongoDB, Tortoise ORM, etc.)
- Documentation improvements
- Test coverage improvements
- Performance improvements

## Reporting bugs

Use the [bug report template](https://github.com/mdfarhankc/fastapi-fullauth/issues/new?template=bug_report.yml) on GitHub Issues.

## Requesting features

Use the [feature request template](https://github.com/mdfarhankc/fastapi-fullauth/issues/new?template=feature_request.yml) on GitHub Issues.

## Code style

- Follow existing patterns in the codebase
- Use type annotations
- Keep functions focused and small
- Log security-sensitive events via `logging.getLogger("fastapi_fullauth.*")`
- Don't add docstrings/comments unless the logic isn't self-evident

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
