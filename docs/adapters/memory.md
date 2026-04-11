# In-Memory Adapter

A simple adapter that stores everything in Python dictionaries. Useful for testing and quick prototyping.

!!! warning
    All data is lost when the process restarts. Do not use in production.

## Usage

```python
from fastapi_fullauth import FullAuth
from fastapi_fullauth.adapters.memory import InMemoryAdapter

fullauth = FullAuth(
    secret_key="dev-secret",
    adapter=InMemoryAdapter(),
)
```

No database, no migrations, no setup. Just works.

## When to use

- **Unit tests** — all fastapi-fullauth tests use this adapter
- **Prototyping** — try out the library without setting up a database
- **Demos** — run the `examples/memory_app` example

## Limitations

- No persistence across restarts
- No concurrent access safety (single-process only)
- OAuth account methods are supported but also in-memory
