from fastapi_fullauth import FullAuth
from fastapi_fullauth.adapters.memory import InMemoryAdapter

fullauth = FullAuth(
    secret_key="change-me-use-a-32-byte-key-here",
    adapter=InMemoryAdapter(),
    include_user_in_login=True,
)
