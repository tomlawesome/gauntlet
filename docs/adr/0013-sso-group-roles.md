# ADR-0013: Roles for SSO accounts come from identity-provider groups

**Status:** Accepted (design ratified on #76; owner answers 2026-10-05)
**Date:** 2026-10-05
**Relates to:** #76 (this change), ADR-0003 (decision 4, which this
amends), ADR-0010 (several admins; every admin keeps a local password and
second factor), #67 (the admin role route and its step-up), #75 (role
changes between user and viewer), #73 (the account-event hook), ADR-0002
(compatibility)

## Context

Every account an SSO sign-in provisions is a `user` (ADR-0003 decision
4), and an admin changes it by hand afterwards. A deployment whose
identity provider already says who is staff and who is a guest has to say
it twice, and the two drift: someone moved out of a group at the provider
keeps the old role here until an admin notices.

## Decision

Pattern: **provider-managed role sync at every sign-in, server admin
excluded** -- Grafana's `role_attribute_path` with
`allow_assign_grafana_admin` off (its default), and Keycloak's broker
mapper in `force` sync mode (re-applied at each login, as against
`import`, which applies at the first only). Authentik puts groups in the
token and leaves the role to the application, which is gauntlet's
position here.

1. **No admin from a group.** `oidc.Policy.RoleFromGroups` maps a group
   to `user` or `viewer`; a value of `admin` is refused at `gate.New`, as
   is any unknown value, and so is a `RoleWithoutGroup` outside the two.
   A compromised or misconfigured provider must not mint admins, and
   ADR-0010 decision 5 gives every admin a local password and second
   factor, which an account minted from a group would lack. An account
   that already holds `admin` is never touched by the map; admin comes
   and goes only through the role route and its step-up (#67).
2. **The provider wins; the role route refuses managed changes.** An
   account is *managed* when it is linked to SSO (`OIDCIssuer` is set),
   the deployment configures a map, and its role is not `admin`. This is
   computed, not stored. `PUT /api/auth/users/{id}/role` to `user` or
   `viewer` on a managed account answers 409 `role-managed-by-sso`
   ("change the group at the identity provider"), before any step-up and
   after the check for an account that already holds the role (`conflict`
   as before). Granting `admin` to a managed account still works, and so
   does demoting an admin to `user`: the map takes over at that
   account's next SSO sign-in. This is Grafana's shape: the role is
   locked in the application where the provider owns it.
3. **Several mapped groups: the highest role.** `Role.AtLeast` decides,
   so the order the provider lists groups in does not matter. Group
   names are matched as `AllowedGroups` are: trimmed, case-insensitive,
   from the claim `GroupsClaim` names.
4. **In no mapped group: `RoleWithoutGroup`, default `viewer`.** Least
   privilege, and the issue's own example ("everyone else a viewer"). An
   operator who wants "guests viewer, everyone else user" sets
   `RoleWithoutGroup: "user"`. Refusing sign-in outright is what
   `AllowedGroups` already does, and the two compose. An absent groups
   claim with a map set means "no group", so the fallback applies; to
   refuse such an identity instead, set `AllowedGroups` too. The owner
   chose `viewer` as the default and the role route's refusal on
   2026-10-05.
5. **Where and when.** At provisioning and at every SSO sign-in in
   `handleOIDCCallback`, in the same store write that finds or creates the
   account (`Store.FindOrCreateOIDCUserWithRole`): there is one save and
   no window where the account has signed in at the old role. Not on the
   link ceremony: a non-admin loses their password on link, so their next
   sign-in is the next SSO sign-in and applies the map. The last-admin
   rule is never reached, since admins are untouched. A change records
   `RoleChangedAt`; a downgrade also `SessionsEndedAt`, ends the account's
   other sessions (the handler drops the in-memory ones, as the role
   route's does), and the sign-in's own session is issued at the new
   role. `Policy.Restricted` is unchanged: the map narrows roles, not
   access.
6. **Audit and notice.** `user.role_changed`, actor `sso`, detail
   `from=user to=viewer; by group map at issuer "<issuer>"; sessions
   ended: all` (the last clause only for a downgrade). `Config.Notices`
   gets `NoticeRoleChanged` with `By` empty and
   `RoleChangeDetail.ViaSSO` true. An account created at its mapped role
   is a creation, not a change, and raises neither.
7. **Compatibility (ADR-0002).** Additions only: `Policy.RoleFromGroups`,
   `Policy.RoleWithoutGroup`, `Policy.Groups`, `Policy.ValidateRoles`,
   `Store.FindOrCreateOIDCUserWithRole`, `OIDCSignIn`,
   `RoleChangeDetail.ViaSSO`, and the error class `role-managed-by-sso`.
   `FindOrCreateOIDCUser` stays and leaves the role alone. No stored field
   is added: `Role`, `RoleChangedAt` and `SessionsEndedAt` already exist,
   so the accounts document stays at version 9 and a version-9 reader
   reads it correctly (#70 is unaffected). With no map configured nothing
   changes.

## Rejected options

- **A per-account "managed" flag.** Rejected: the state is already
  derivable from the link and the configuration, and a stored flag could
  disagree with both and would change the document.
- **Let the admin change the role and silently revert it at the next
  sign-in.** Rejected: an admin who is told "done" and finds it undone a
  day later has been lied to; refusing says where the change belongs.
- **Admin by group.** Rejected: see decision 1.
- **A stored role field set by the provider.** Rejected: nothing new is
  needed; the existing role, read from the store on every request, is the
  source of truth, and the map is only how it is written.
- **Highest-first expression, as Grafana's `role_attribute_path`.**
  Rejected for a map: a map has no order to write highest-first in, so the
  rule is "highest wins" and is order-independent.

## Consequences

- An operator can run roles entirely from the provider: move someone out
  of a group and their next sign-in lowers the role and ends their other
  sessions. Until that sign-in the old role stands, as with any claim read
  at login; it is not a back-channel.
- A deployment that sets a map has every SSO account's role decided by
  the provider, except for admins. To make someone an admin, an admin
  grants it with the step-up; to make them a non-admin again, demote them,
  and the map applies from their next SSO sign-in.
- A person whose groups claim goes missing (a provider misconfiguration)
  falls to the fallback role at their next sign-in, `viewer` by default:
  the failure is toward less access, not more.
- Applications that switch on `NoticeRoleChanged` see changes with an
  empty `By` and `ViaSSO` set.
