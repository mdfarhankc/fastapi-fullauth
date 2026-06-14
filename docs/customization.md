# Customization

FastAPI FullAuth is pluggable, not prescriptive. Almost every part can be swapped or extended without forking the library. This page is the map of every customization seam, with a link straight to the relevant guide.

<div class="grid cards" markdown>

- **Your own database**

    Implement the adapter interface for MongoDB, Tortoise, DynamoDB, or any store. [Writing a custom adapter](adapters/custom.md) has a complete worked example.

- **Custom user fields**

    Extend `UserSchema` / `CreateUserSchema` with your own columns and control which ones `PATCH /me` may touch. See [Custom schemas](adapters/index.md#custom-schemas).

- **Token claims**

    Embed your own data in the JWT (tenant id, plan, feature flags) with a claims builder. See [Custom token claims](auth/custom-claims.md).

- **Event hooks**

    Run your code after register, login, verify, password reset, and more. See [Event hooks](auth/hooks.md).

- **Password rules**

    Plug in your own validation, strength rules, or hashing scheme. See [Password validation](auth/passwords.md).

- **Token transport**

    Switch between bearer headers and httponly cookies, or run both. See [Cookies](configuration.md#cookies) and [Frontend integration](frontend-integration.md).

- **Which routes mount**

    Mount the combined router or pick individual sub-routers, and change the URL prefix. See [Getting Started](getting-started.md) and [Architecture](architecture.md).

- **Login field**

    Authenticate by username (or any field) instead of email by overriding `get_user_by_field`. See [Writing a custom adapter](adapters/custom.md#logging-in-with-a-field-other-than-email).

- **Everything else**

    Token lifetimes, lockout, rate limits, CSRF, security headers, and storage backends are all configurable. See [Configuration](configuration.md).

</div>

## How extensibility works

Two mechanisms cover most of the surface:

- **Adapters and mixins.** The [adapter](adapters/index.md) is the database seam. Inherit an optional mixin (roles, permissions, OAuth, passkeys, sessions) and the matching router mounts automatically; leave it out and the feature is simply absent - no dead endpoints. See [adapter architecture](adapters/index.md#adapter-architecture).
- **Configuration and hooks.** [`FullAuthConfig`](configuration.md) tunes behavior declaratively, while [event hooks](auth/hooks.md) and [token claims](auth/custom-claims.md) let you inject code at the right moments without subclassing the routers.

## Worked combinations

The [Recipes](recipes.md) page ties these seams together in complete, copyable examples - a multi-tenant SaaS (custom field + claims + dependency) and username-based login, among others.

If something isn't covered here, the [API reference](api-reference.md) lists every public type, and the [architecture overview](architecture.md) explains how the layers fit together.
