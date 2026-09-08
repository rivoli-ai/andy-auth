# Service role grants

Auth administrators can open **Admin → Users → Service roles** for a user, create
a named service role, and grant or remove memberships individually. Creation does
not automatically grant the role. Use the exact names expected by consumers, for
example `AHP Viewer` or `AHP Reviewer`. Identity treats names case-insensitively and
preserves the catalog spelling in claims. Existing roles can be reused across users.

Auth owns these grants under the current contract. It does not import manifest
`rbac.roles` automatically or move authority into andy-rbac. Such a change requires
coordinating downstream authorization policies. Role names and their interpretation
must agree with the consumer's RBAC seed. Roles are issued only when the client is
allowed to request, and requests, the `roles` scope. Manifest scope entries can be
plain names or already `scp:`-prefixed permissions.

Admin/User membership remains in the existing user controls, including last-admin
protection. Changing that built-in membership preserves service roles. The service
role page cannot create, grant or remove Admin/User, and all mutations require the
admin Identity cookie and an antiforgery token. Changes are recorded in the audit log.

Membership changes invoke the existing access-revocation service to revoke sessions,
authorizations and tokens and rotate the security stamp. The user signs in again for
updated claims. Offline JWT consumers can still accept an older token until expiry;
this feature does not establish immediate cross-service revocation (tracked in #172).
Role creation/grant/removal is supported; global role renaming/deletion is deliberately
absent to avoid silently changing consumer contracts or every user's memberships.
