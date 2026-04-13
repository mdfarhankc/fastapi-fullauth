from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter

fullauth = FullAuth(
    adapter=InMemoryAdapter(),
    config=FullAuthConfig(SECRET_KEY="change-me-use-a-32-byte-key-here"),
    include_user_in_login=True,
)
