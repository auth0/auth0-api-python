# Organization Policy

The SDK can enforce that incoming access tokens carry a valid Auth0 Organization (`org_id` claim). This is useful for APIs that serve B2B customers where every request must be scoped to an Organization, optionally restricted to a specific set of Organizations.

## Policy Modes

### Allow (Default)

By default, `organization_policy` is `"allow"`. The SDK uses the `org_id` claim when present but does not require it. This is the pre-existing behavior of `verify_access_token`, so existing callers see no change unless they opt in to `"required"`.

```python
from auth0_api_python import ApiClient, ApiClientOptions

api_client = ApiClient(ApiClientOptions(
    domain="tenant.auth0.com",
    audience="https://api.example.com"
    # organization_policy defaults to "allow"
))

# Tokens with or without an org_id claim are both accepted
claims = await api_client.verify_access_token(access_token)
```

### Required

Set `organization_policy="required"` to reject any token that has no `org_id` claim:

```python
api_client = ApiClient(ApiClientOptions(
    domain="tenant.auth0.com",
    audience="https://api.example.com",
    organization_policy="required"
))

# Raises MissingOrganizationError if the token has no org_id claim
claims = await api_client.verify_access_token(access_token)
```

## Organization Allowlist

When `organization_policy="required"`, you can additionally restrict which Organizations are accepted with `organization_id`. It takes a single `org_id` claim value or a list of them:

```python
api_client = ApiClient(ApiClientOptions(
    domain="tenant.auth0.com",
    audience="https://api.example.com",
    organization_policy="required",
    organization_id=["org_abc123", "org_def456"]
))
```

`organization_id` compares the opaque `org_id` claim value directly (string comparison, no network call). It does not accept or resolve the human-readable Organization name.

## Error Handling

### Configuration Errors

Raised at initialization when the SDK configuration is invalid:

```python
from auth0_api_python import ApiClient, ApiClientOptions, ConfigurationError

# organization_id passed with the default "allow" policy
try:
    api_client = ApiClient(ApiClientOptions(
        domain="tenant.auth0.com",
        audience="https://api.example.com",
        organization_id="org_abc123"
    ))
except ConfigurationError as e:
    print(e)            # "organization_id is only valid when organization_policy is 'required'"
    e.get_status_code() # 500
    e.get_error_code()  # "invalid_configuration"
```

### Missing Organization

Raised when `organization_policy="required"` and the token has no `org_id` claim:

```python
from auth0_api_python import MissingOrganizationError

try:
    claims = await api_client.verify_access_token(access_token)
except MissingOrganizationError as e:
    print(e)            # "Token missing required 'org_id' claim"
    e.get_status_code() # 401
    e.get_error_code()  # "missing_organization"
```

### Organization Not Allowed

Raised when the token's `org_id` is not in the `organization_id` allowlist:

```python
from auth0_api_python import OrganizationNotAllowedError

try:
    claims = await api_client.verify_access_token(access_token)
except OrganizationNotAllowedError as e:
    print(e)            # "Organization 'org_xyz' is not in the allowed list"
    e.get_status_code() # 401
    e.get_error_code()  # "organization_not_allowed"
```

> [!NOTE]
> `MissingOrganizationError` and `OrganizationNotAllowedError` are both subclasses of `VerifyAccessTokenError`. `WWW-Authenticate` response headers (via `get_headers()`) are only populated when the token is verified through `verify_request()`, which wraps these errors before re-raising. Calling `verify_access_token()` directly does not attach response headers.
