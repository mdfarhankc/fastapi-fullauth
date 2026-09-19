# Customization

FastAPI FullAuth is pluggable, not prescriptive. Almost every part can be swapped or extended without forking the library. This page is the map of every customization seam, with a link straight to the relevant guide.

- **Your own database**

  Implement the adapter interface for MongoDB, Tortoise, DynamoDB, or any store. [Writing a custom adapter](https://mdfarhankc.github.io/fastapi-fullauth/adapters/custom/index.md) has a complete worked example.

- **Custom user fields**

  Extend `UserSchema` / `CreateUserSchema` with your own columns and control which ones `PATCH /me` may touch. See [Custom schemas](https://mdfarhankc.github.io/fastapi-fullauth/adapters/#custom-schemas).

- **Token claims**

  Embed your own data in the JWT (tenant id, plan, feature flags) with a claims builder. See [Custom token claims](https://mdfarhankc.github.io/fastapi-fullauth/auth/custom-claims/index.md).

- **Event hooks**

  Run your code after register, login, verify, password reset, and more. See [Event hooks](https://mdfarhankc.github.io/fastapi-fullauth/auth/hooks/index.md).

- **Password rules**

  Plug in your own validation, strength rules, or hashing scheme. See [Password validation](https://mdfarhankc.github.io/fastapi-fullauth/auth/passwords/index.md).

- **Token transport**

  Switch between bearer headers and httponly cookies, or run both. See [Cookies](https://mdfarhankc.github.io/fastapi-fullauth/configuration/#cookies) and [Frontend integration](https://mdfarhankc.github.io/fastapi-fullauth/frontend-integration/index.md).

- **Which routes mount**

  Mount the combined router or pick individual sub-routers, and change the URL prefix. See [Getting Started](https://mdfarhankc.github.io/fastapi-fullauth/getting-started/index.md) and [Architecture](https://mdfarhankc.github.io/fastapi-fullauth/architecture/index.md).

- **Login field**

  Authenticate by username (or any field) instead of email by overriding `get_user_by_field`. See [Writing a custom adapter](https://mdfarhankc.github.io/fastapi-fullauth/adapters/custom/#logging-in-with-a-field-other-than-email).

- **Everything else**

  Token lifetimes, lockout, rate limits, CSRF, security headers, and storage backends are all configurable. See [Configuration](https://mdfarhankc.github.io/fastapi-fullauth/configuration/index.md).

## How extensibility works

Two mechanisms cover most of the surface:

- **Adapters and mixins.** The [adapter](https://mdfarhankc.github.io/fastapi-fullauth/adapters/index.md) is the database seam. Inherit an optional mixin (roles, permissions, OAuth, passkeys, sessions) and the matching router mounts automatically; leave it out and the feature is simply absent - no dead endpoints. See [adapter architecture](https://mdfarhankc.github.io/fastapi-fullauth/adapters/#adapter-architecture).
- **Configuration and hooks.** [`FullAuthConfig`](https://mdfarhankc.github.io/fastapi-fullauth/configuration/index.md) tunes behavior declaratively, while [event hooks](https://mdfarhankc.github.io/fastapi-fullauth/auth/hooks/index.md) and [token claims](https://mdfarhankc.github.io/fastapi-fullauth/auth/custom-claims/index.md) let you inject code at the right moments without subclassing the routers.

## Worked combinations

The [Recipes](https://mdfarhankc.github.io/fastapi-fullauth/recipes/index.md) page ties these seams together in complete, copyable examples - a multi-tenant SaaS (custom field + claims + dependency) and username-based login, among others.

If something isn't covered here, the [API reference](https://mdfarhankc.github.io/fastapi-fullauth/api-reference/index.md) lists every public type, and the [architecture overview](https://mdfarhankc.github.io/fastapi-fullauth/architecture/index.md) explains how the layers fit together.
