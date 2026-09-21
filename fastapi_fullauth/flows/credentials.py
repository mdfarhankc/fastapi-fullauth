"""The rule for removing one of a user's sign-in methods.

Unlinking an OAuth provider and deleting a passkey are the same question asked
twice: would this leave the account with no way back in? Both routes ask it here
so they cannot drift apart.
"""

from collections.abc import Collection
from uuid import UUID

from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
)
from fastapi_fullauth.types import UserID


async def remaining_login_methods(
    adapter: AbstractUserAdapter,
    user_id: UserID,
    *,
    usable_providers: Collection[str],
    passkeys_usable: bool,
    without_provider: str | None = None,
    without_passkey_id: UUID | None = None,
) -> int:
    """How many ways the user could still sign in once the named credential is gone.

    Counts only what this deployment can actually serve. A stored credential for
    a disabled feature is not a way back in: a passkey row survives turning
    ``PASSKEY_ENABLED`` off, and an OAuth account survives dropping its provider
    from the configured list, but neither can be signed in with. Counting those
    would allow exactly the lockout this check exists to prevent, so the caller
    passes the providers it has configured and whether passkey sign-in is live.
    """
    count = 0
    if await adapter.get_hashed_password(user_id) is not None:
        count += 1

    if (
        usable_providers
        and adapter.supports_feature("oauth")
        and isinstance(adapter, OAuthAdapterMixin)
    ):
        count += sum(
            1
            for account in await adapter.get_user_oauth_accounts(user_id)
            if account.provider != without_provider and account.provider in usable_providers
        )

    if (
        passkeys_usable
        and adapter.supports_feature("passkey")
        and isinstance(adapter, PasskeyAdapterMixin)
    ):
        count += sum(
            1
            for passkey in await adapter.get_user_passkeys(user_id)
            if passkey.id != without_passkey_id
        )

    return count


def last_method_detail(*, passkeys_available: bool) -> str:
    """The 400 body for refusing to remove the last sign-in method.

    Names only the alternatives this deployment actually offers, so it never
    tells someone to do something the app does not support.
    """
    alternative = " or add a passkey" if passkeys_available else ""
    return f"Cannot remove your only sign-in method. Set a password{alternative} first."
