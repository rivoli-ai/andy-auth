# Admin UI Guide

Admin dashboard documentation for managing users, OAuth clients, and audit logs.

## Overview

The admin dashboard provides a web-based interface for managing Andy Auth Server. Access it at:

**Development:** https://localhost:7088/Admin
**Production:** https://auth.rivoli.ai/Admin

## Features

### 1. Dashboard

**Path:** `/Admin` or `/Admin/Index`

**Overview Cards:**
- Total Users
- Active Users
- OAuth Clients
- Today's Logins

**Recent Activity:**
- Last 10 user logins
- Registration events
- Account suspensions

**Quick Actions:**
- Create new user
- Add OAuth client
- View audit logs

### 2. User Management

**Path:** `/Admin/Users`

**User List Features:**
- Search by email or name
- Filter by status (active, suspended, deleted)
- Sort by last login, created date
- Pagination (50 users per page)

**User Actions:**
- **View Details**: Full user profile
- **Suspend**: Temporarily disable account
- **Unsuspend**: Re-enable suspended account
- **Set Expiration**: Account expires after date
- **Soft Delete**: Mark account as deleted (reversible)
- **Permanently Delete**: Remove account completely

**User Card Information:**
- Email address
- Full name
- Last login time
- Account status (active, suspended, expired, deleted)
- Creation date

### 3. Suspend User

**Path:** `/Admin/Users/{id}/Suspend`

**Form Fields:**
- **Reason** (required): Why the account is being suspended
- **Expiration Date** (optional): When to automatically unsuspend

**Effects:**
- User cannot log in
- Existing sessions are revoked
- Audit log entry created
- User is notified (if email configured)

**Use Cases:**
- Policy violations
- Security incidents
- Temporary account freeze
- Investigation pending

### 4. Soft Delete

**Path:** `/Admin/Users/{id}/SoftDelete`

**Behavior:**
- User marked as deleted (IsDeleted = true)
- User cannot log in
- Data retained in database
- Can be restored later
- Audit trail maintained

**Difference from Suspend:**
- Suspension is temporary
- Deletion is permanent intent
- Different audit log category

### 5. OAuth Client Management

**Path:** `/Admin/Clients`

**Client List:**
- Client ID
- Display Name
- Type (Confidential/Public)
- Redirect URIs
- Created date

**Seeded Clients:**

**lexipro-api** (Confidential)
- Client ID: `lexipro-api`
- Has client secret (hashed)
- Redirect URIs:
  - https://localhost:7001/callback
  - http://localhost:7001/callback
  - https://lexipro-api.rivoli.ai/callback
- Permissions:
  - Authorization endpoint
  - Token endpoint
  - Refresh token grant
  - Authorization code grant

**wagram-web** (Public)
- Client ID: `wagram-web`
- No client secret (public SPA)
- Redirect URIs:
  - https://wagram.ai/callback
  - http://localhost:4200/callback
- Permissions:
  - Authorization endpoint
  - Token endpoint
  - Refresh token grant
  - Authorization code grant
  - PKCE required

**claude-desktop** (Public)
- Client ID: `claude-desktop`
- No client secret
- Redirect URIs: `http://127.0.0.1:*`
- Permissions:
  - Authorization endpoint
  - Token endpoint
  - Refresh token grant
  - Authorization code grant
  - PKCE required

**Future Features:**
- [ ] Create new OAuth clients via UI
- [ ] Edit client redirect URIs
- [ ] Rotate client secrets
- [ ] View client usage statistics
- [ ] Revoke all tokens for a client

### 6. Audit Logs

**Path:** `/Admin/AuditLogs`

**Log Entries Include:**
- Timestamp
- User (email)
- Action (Login, Register, Suspend, etc.)
- Entity (User, Client, Token)
- IP Address
- User Agent
- Result (Success/Failure)
- Changes (JSON diff)

**Filterable By:**
- Date range
- Action type
- User
- Result (success/failure)

**Logged Events:**
- User login (successful/failed)
- User registration
- Password change
- Account suspension/unsuspension
- Account deletion/restoration
- User profile updates
- OAuth token issuance
- Token revocation
- Client creation/modification

**Retention:**
- Development: 90 days
- Production: 1 year (configurable)

### 7. Navigation

**Top Navigation Bar:**
- Dashboard
- OAuth Clients
- Users
- Audit Logs

**User Menu:**
- Logged in as: [email]
- Logout

## Access Control

### Authentication Required

All admin pages require authentication. Unauthenticated users are redirected to login.

### Authorization (Future)

Currently all authenticated users can access admin. Future enhancements:

- **Admin Role**: Full access to all features
- **Support Role**: Read-only access to users and logs
- **Auditor Role**: Read-only access to logs only

**Implementation:**
```csharp
[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    // ...
}
```

## UI Design

### Design System

**Color Palette:**
- Primary: #0066CC (blue)
- Success: #28A745 (green)
- Warning: #FFC107 (yellow)
- Danger: #DC3545 (red)
- Surface: #FFFFFF (white)
- Background: #F8F9FA (light gray)

**Typography:**
- Font: Inter (sans-serif)
- Headings: 600-700 weight
- Body: 400 weight

**Components:**
- Cards with rounded corners (12px)
- Buttons with hover states
- Tables with alternating rows
- Form inputs with focus states
- Status badges (active, suspended, etc.)

### Responsive Design

**Desktop (1200px+):**
- Full navigation sidebar
- Multi-column layouts
- Data tables with all columns

**Tablet (768-1199px):**
- Collapsed navigation
- Two-column layouts
- Scrollable tables

**Mobile (< 768px):**
- Hamburger menu
- Single column
- Card-based layouts
- Simplified tables

## User Workflows

### Suspend a User

1. Navigate to Users page
2. Find user (search or scroll)
3. Click "Suspend" button
4. Fill in reason and optional expiration
5. Click "Suspend Account"
6. User is immediately suspended
7. Audit log entry created

### Review Audit Logs

1. Navigate to Audit Logs
2. Filter by date range (optional)
3. Filter by action type (optional)
4. Filter by user (optional)
5. Review entries in chronological order
6. Click entry to see full details

### Monitor Recent Activity

1. Navigate to Dashboard
2. View "Recent Activity" section
3. See last 10 login events
4. Click event to see full audit log entry

## Security Considerations

### CSRF Protection

All forms include anti-forgery tokens:
```html
<form asp-controller="Admin" asp-action="SuspendUser" method="post">
    @* Anti-forgery token auto-included *@
</form>
```

### Input Validation

- Email: Must be valid email format
- Dates: Must be valid dates
- Reason: Required for suspension
- SQL Injection: Prevented by EF Core parameterized queries
- XSS: Prevented by Razor auto-encoding

### Authorization Checks

All admin actions verify:
1. User is authenticated
2. User has admin role (future)
3. Action is authorized for target entity
4. Audit log entry created

### Rate Limiting

Admin endpoints are rate-limited:
- 60 requests per minute per IP
- Higher limit than public endpoints
- Prevents automated abuse

## API Endpoints (For Reference)

**User Management:**
- `GET /Admin/Users` - List users
- `GET /Admin/Users/{id}` - User details
- `POST /Admin/Users/{id}/Suspend` - Suspend user
- `POST /Admin/Users/{id}/Unsuspend` - Unsuspend user
- `POST /Admin/Users/{id}/SoftDelete` - Soft delete user
- `DELETE /Admin/Users/{id}` - Permanent delete

**OAuth Clients:**
- `GET /Admin/Clients` - List OAuth clients
- `GET /Admin/Clients/{id}` - Client details

**Audit Logs:**
- `GET /Admin/AuditLogs` - List audit logs
- `GET /Admin/AuditLogs?action=Login` - Filter by action
- `GET /Admin/AuditLogs?userId={id}` - Filter by user

**Dashboard:**
- `GET /Admin` - Dashboard with stats

## Future Enhancements

### Phase 1 (Short Term)
- [ ] Role-based access control
- [ ] Bulk user operations
- [ ] Export audit logs to CSV
- [ ] Email notifications for admin actions
- [ ] User impersonation (for support)

### Phase 2 (Medium Term)
- [ ] OAuth client creation/editing via UI
- [ ] Client usage statistics
- [ ] Token management (view, revoke)
- [ ] Advanced filtering and search
- [ ] Dashboard charts and graphs

### Phase 3 (Long Term)
- [ ] Two-factor authentication for admin
- [ ] Audit log anomaly detection
- [ ] Automated security alerts
- [ ] User behavior analytics
- [ ] Compliance reports (GDPR, SOC 2)

## Troubleshooting

### "Access Denied" when accessing admin

**Solution:**
- Ensure you're logged in
- Check that your account is active
- Verify admin role is assigned (future)

### Users not appearing in list

**Solution:**
- Check that users exist in database
- Verify IsDeleted filter is correct
- Check pagination settings

### Audit logs not showing

**Solution:**
- Verify database connection
- Check that audit logging is enabled
- Ensure sufficient permissions

### Suspension not taking effect

**Solution:**
- Check that IsSuspended flag is set
- Verify user logs out and tries to log in again
- Check audit logs for suspension event

## Developer Notes

### Adding New Admin Features

1. Create controller action in `AdminController.cs`
2. Add corresponding view in `Views/Admin/`
3. Update navigation in `_Layout.cshtml`
4. Add authorization attribute
5. Add audit logging
6. Write tests

### Modifying User Model

1. Update `ApplicationUser` class
2. Create migration: `dotnet ef migrations add UpdateUser`
3. Update views to show new fields
4. Update audit logging to track changes
5. Test thoroughly

### Custom Audit Log Actions

```csharp
await _auditLogger.LogAsync(new AuditLog
{
    Action = "CustomAction",
    Entity = "EntityName",
    EntityId = id,
    UserId = currentUserId,
    UserEmail = currentUserEmail,
    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
    Changes = JsonSerializer.Serialize(changes),
    Result = "Success"
});
```

## References

- [ASP.NET Core Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity)
- [Razor Pages](https://learn.microsoft.com/en-us/aspnet/core/razor-pages/)
- [Entity Framework Core](https://learn.microsoft.com/en-us/ef/core/)
- [GDPR Compliance](https://gdpr.eu/)

---

**Last Updated:** 2025-11-16
