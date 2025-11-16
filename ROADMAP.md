# Andy Auth - Implementation Roadmap

## Executive Summary

Andy.Auth.Server is an OAuth 2.0 / OpenID Connect authentication server built on OpenIddict. This roadmap outlines the path from current state (development) → UAT → Production → Post-Production enhancements.

**Current Status:** Core MVP complete, 80% admin UI complete, 95% tests passing

**Goal:** Replace Clerk with self-hosted OAuth for AI assistants (ChatGPT, Claude Desktop, Cline, Roo)

---

## Phase Overview

| Phase | Timeline | Focus | Issues |
|-------|----------|-------|--------|
| **Pre-UAT** | 3-5 days | Complete MVP, testing, security | #1, #4, #5 |
| **UAT** | 1 week | Deploy, test multi-assistant compat | #3, #7, #2 |
| **Production** | 1 week | Deploy production, monitoring | #8 |
| **Post-Production** | Ongoing | Enterprise features, Azure AD | #6, #10-16, #9 |

**Total to Production:** ~3 weeks

---

## ✅ Completed Features

### Core OAuth/OIDC (Sprint 1)
- Andy.Auth library with multi-provider support
- Andy.Auth.Server with OpenIddict
- Authorization Code Flow with PKCE
- Client Credentials Flow
- Refresh Token Flow
- OpenID Discovery endpoint (/.well-known/openid-configuration)
- JWT token issuance, introspection, revocation
- UserInfo endpoint
- PostgreSQL database with Entity Framework migrations
- ASP.NET Core Identity user management
- HTTPS development certificates
- OAuth client seeding (lexipro-api, wagram-web, claude-desktop)

### Admin UI (Sprint 2 - Just Completed!)
- Dashboard home with statistics
- OAuth clients viewing
- Users management (view, paginate, suspend, set expiration, delete)
- Audit logging for all administrative actions
- Audit logs viewing page
- Clean Lexipro-style UI (no gradients, SVG icons, Inter font)
- User email/password authentication

### Testing (95% Complete)
- 77/81 tests passing
- DbSeeder tests (9/9)
- AccountController tests (16/16)
- Integration tests (3/7 - 4 need env fixes)
- Test project structure with xUnit + Moq

---

## 🏃 Pre-UAT Phase (Week 1)

**Goal:** Production-ready MVP

### Issue #1: Complete Testing Suite (HIGH) - 2 days
**Status:** 95% complete (77/81 tests passing)

**Remaining Tasks:**
- [ ] Add AuthorizationController unit tests (10-15 tests)
- [ ] Fix 4 integration tests (HTTPS + in-memory DB config)
- [ ] Add end-to-end OAuth flow tests
- [ ] Achieve ≥70% code coverage

**Acceptance Criteria:**
- All 85+ tests passing
- Code coverage ≥70%
- CI/CD pipeline green

**Priority:** HIGH - Quality gate before UAT

---

### Issue #4: Security Hardening (CRITICAL) - 2-3 days
**Status:** Not started

**Tasks:**
- [ ] Add rate limiting middleware (AspNetCoreRateLimit)
  - Authentication: 5 attempts/min
  - Token endpoint: 10 requests/min
  - Registration: 3 attempts/hour
- [ ] Configure security headers
  - HSTS (Strict-Transport-Security)
  - CSP (Content-Security-Policy)
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
- [ ] Brute force protection (lock after 5 failed attempts)
- [ ] Account lockout policies (30-minute lockout)
- [ ] CSRF protection verification
- [ ] SQL injection testing
- [ ] XSS protection testing

**Acceptance Criteria:**
- Rate limiting active on all sensitive endpoints
- Security headers configured
- Account lockout working
- No critical vulnerabilities
- Security audit documented

**Priority:** CRITICAL - Must complete before UAT

---

### Issue #5: Admin Dashboard UI (MEDIUM) - Remaining Work
**Status:** 80% complete (just finished core features!)

**Completed:**
- ✅ Dashboard home with stats
- ✅ OAuth clients viewing
- ✅ Users viewing/management
- ✅ Audit logs page
- ✅ Clean UI design

**Remaining Tasks:**
- [ ] Create/Edit/Delete OAuth clients (#14)
- [ ] Regenerate client secrets (#14)
- [ ] Search users by email/name
- [ ] View user's active sessions (depends on #11)

**Note:** Core admin UI is done. Remaining features moved to #14 (post-production).

**Priority:** MEDIUM - Nice to have, not blocking UAT

---

## 🧪 UAT Phase (Week 2)

**Goal:** Deploy to Railway UAT, validate with all AI assistants

### Issue #3: Railway UAT Deployment (HIGH) - 1 day
**Status:** Not started

**Tasks:**
- [ ] Create Railway project for Andy.Auth.Server
- [ ] Provision PostgreSQL database with backups
- [ ] Configure environment variables (UAT)
- [ ] Set up custom domain (auth-uat.rivoli.ai)
- [ ] Configure SSL/TLS certificates
- [ ] Run database migrations
- [ ] Seed OAuth clients (lexipro-api, wagram-web, claude-desktop)
- [ ] Test OpenID Discovery endpoint
- [ ] Monitor logs and performance

**Environment Variables:**
```
ConnectionStrings__DefaultConnection
ASPNETCORE_ENVIRONMENT=UAT
OpenIddict__Server__EncryptionKey
OpenIddict__Server__SigningKey
Mcp__ServerUrl=https://auth-uat.rivoli.ai
```

**Acceptance Criteria:**
- Server deployed at https://auth-uat.rivoli.ai
- Database migrations applied successfully
- OAuth clients seeded
- OpenID Discovery working
- Health checks passing (basic)
- Logs accessible in Railway dashboard

**Priority:** HIGH - Enables UAT testing

---

### Issue #7: Multi-Assistant Compatibility Testing (CRITICAL) - 3-4 days
**Status:** Not started

**Goal:** Ensure ALL AI assistants work correctly

**Platforms to Test:**
1. **ChatGPT** - OpenAI's assistant with MCP
2. **Cline** (formerly Claude Dev) - VS Code extension
3. **Claude Desktop** - Anthropic's desktop app
4. **Roo** - VS Code extension for Claude
5. **Continue.dev** (bonus if applicable)

**Tasks:**
- [ ] Add OAuth clients for each assistant
- [ ] Test ChatGPT MCP discovery and OAuth flow
- [ ] Test Cline authentication flow
- [ ] Test Claude Desktop (resolve previous auth loops!)
- [ ] Test Roo authentication
- [ ] Test concurrent sessions across assistants
- [ ] Test token refresh for all assistants
- [ ] Document setup for each platform

**Acceptance Criteria:**
- All 4 assistants can successfully authenticate
- NO authorization loops occur
- Tokens work and refresh correctly
- MCP discovery works from all platforms
- All assistants can access Lexipro.Api protected endpoints
- Comprehensive documentation for each platform

**Priority:** CRITICAL - This is the core use case!

---

### Issue #2: Lexipro.Api Integration (HIGH) - 2-3 days
**Status:** Not started

**Tasks:**
- [ ] Update Lexipro.Api to reference Andy.Auth NuGet package
- [ ] Configure AndyAuth provider in Lexipro.Api
- [ ] Remove Clerk dependencies from Lexipro.Api
- [ ] Update MCP metadata to point to auth-uat.rivoli.ai
- [ ] Test OAuth Authorization Code Flow
- [ ] Test token validation
- [ ] Test user claims extraction
- [ ] Test with all AI assistants
- [ ] Verify all Lexipro.Api functionality works

**Acceptance Criteria:**
- Lexipro.Api successfully authenticates with Andy.Auth.Server
- MCP discovery endpoint works
- All AI assistants can connect
- All existing Lexipro.Api functionality works
- No regression in Lexipro features

**Priority:** HIGH - Validates the entire system

---

## 🚀 Production Phase (Week 3)

### Issue #8: Production Deployment to Railway (CRITICAL) - 2-3 days
**Status:** Not started

**Prerequisites:**
- ✅ UAT deployment successful (#3)
- ✅ All tests passing (#1)
- ✅ Security hardening complete (#4)
- ✅ Multi-assistant testing complete (#7)

**Tasks:**

**Railway Configuration:**
- [ ] Create Railway production project
- [ ] Provision production PostgreSQL with backups enabled
- [ ] Configure custom domain (auth.rivoli.ai)
- [ ] Set up environment variables (PROD)
- [ ] Configure SSL/TLS certificates
- [ ] Enable automatic deployments from main branch
- [ ] Configure resource limits and scaling

**Database:**
- [ ] Run migrations on production database
- [ ] Seed production OAuth clients
- [ ] Configure database connection pooling
- [ ] Enable automated daily backups
- [ ] Set up backup retention policy (30 days)
- [ ] Test database restore procedure

**Monitoring & Observability:**
- [ ] Set up Railway logging
- [ ] Configure log retention
- [ ] Add health check endpoints (/health, /ready)
- [ ] Set up uptime monitoring (UptimeRobot / Pingdom)
- [ ] Configure error tracking (Sentry / App Insights)
- [ ] Set up custom metrics dashboards

**Alerting:**
- [ ] Alert on service downtime
- [ ] Alert on high error rates
- [ ] Alert on database failures
- [ ] Alert on certificate expiration (30 days warning)

**Documentation:**
- [ ] Document deployment process
- [ ] Create runbook for common issues
- [ ] Document rollback procedures
- [ ] Document scaling procedures
- [ ] Create disaster recovery plan
- [ ] Create incident response plan

**Go-Live:**
- [ ] All tests pass in production
- [ ] Security audit complete
- [ ] Backup/restore tested
- [ ] Monitoring active
- [ ] Alerts configured
- [ ] Update Lexipro.Api to point to auth.rivoli.ai
- [ ] Update all OAuth client configurations
- [ ] Migrate from Clerk

**Acceptance Criteria:**
- Service deployed at https://auth.rivoli.ai
- All OAuth flows working
- All AI assistants can authenticate
- Monitoring and alerts active
- Backups running daily
- Documentation complete
- Zero downtime deployment configured
- Clerk migration successful

**Priority:** CRITICAL - Final production deployment

---

## 📈 Post-Production Enhancements (Ongoing)

### Priority 1: Enterprise Features

#### Issue #6: Azure AD / Microsoft Entra ID Integration (HIGH) - 3-4 days
**Why:** Enterprise SSO, leverage existing Azure AD identities

**Tasks:**
- [ ] Install Microsoft.Identity.Web NuGet package
- [ ] Configure Azure AD authentication
- [ ] Add "Sign in with Microsoft" button
- [ ] Handle external authentication callbacks
- [ ] Link external accounts to local accounts
- [ ] Map Azure AD claims
- [ ] Add external provider info to user profile
- [ ] Test Azure AD sign-in flow
- [ ] Document Azure AD app registration

**Acceptance Criteria:**
- Users can sign in with Azure AD accounts
- Claims properly mapped
- Account linking works
- Works across dev/uat/prod

**Priority:** HIGH - Important for enterprise adoption

---

#### Issue #11: Session Management + Back-Channel Logout (HIGH) - 4-5 days
**Why:** Track sessions, notify clients on logout

**Tasks:**
- [ ] Create UserSessions table
- [ ] Track sessions on login
- [ ] Add "Active Sessions" page in user profile
- [ ] Add session revocation
- [ ] Configure concurrent session limits
- [ ] Implement session timeout
- [ ] Implement back-channel logout
- [ ] Send logout notifications to OAuth clients

**Acceptance Criteria:**
- Sessions tracked in database
- Users can view/revoke sessions
- Concurrent limits enforced
- Back-channel logout works

**Priority:** HIGH - Important for production security

---

#### Issue #12: Two-Factor Authentication (2FA) (HIGH) - 3-4 days
**Why:** Enhanced security, enterprise requirement

**Tasks:**
- [ ] Add 2FA setup page with QR code
- [ ] Support TOTP (Google Authenticator, etc.)
- [ ] Generate recovery codes
- [ ] Add 2FA login flow
- [ ] Support "Remember this device"
- [ ] Add 2FA status to admin UI
- [ ] Allow admin to disable 2FA

**Acceptance Criteria:**
- Users can enable 2FA with authenticator apps
- Recovery codes work
- "Remember device" works
- Admin can manage 2FA

**Priority:** HIGH - Important for production

---

### Priority 2: Admin & Operations

#### Issue #10: User Consent Management (MEDIUM) - 3-4 days
**Why:** GDPR compliance, user trust, security

**Tasks:**
- [ ] Create consent screen UI
- [ ] Show requested scopes to users
- [ ] Store consent decisions
- [ ] Add consent revocation in user profile
- [ ] Skip consent if previously granted
- [ ] Add audit logging for consents

**Acceptance Criteria:**
- First-time authorization shows consent screen
- Users can revoke consents
- Consent screen works with all flows

**Priority:** MEDIUM - Important for production, GDPR

---

#### Issue #14: OAuth Client CRUD in Admin UI (MEDIUM) - 3-4 days
**Why:** Self-service client management

**Tasks:**
- [ ] Add "Create OAuth Client" page
- [ ] Add client editing
- [ ] Add client deletion with confirmation
- [ ] Add client secret regeneration
- [ ] Validate redirect URIs
- [ ] Log all operations in audit

**Acceptance Criteria:**
- Admins can create/edit/delete clients via UI
- Client secrets shown only once
- All operations logged

**Priority:** MEDIUM - Enhances operations

---

### Priority 3: Advanced Features (Future)

#### Issue #13: Reference Tokens (MEDIUM-LOW) - 2-3 days
**Why:** Better revocation, audit trail

**Tasks:**
- [ ] Configure OpenIddict for reference tokens
- [ ] Add client-level token type configuration
- [ ] Implement token introspection
- [ ] Add immediate revocation
- [ ] Add token cleanup job

**Priority:** MEDIUM-LOW - Nice to have

---

#### Issue #15: Advanced OAuth Flows (LOW) - 5-7 days
**Flows:** Device Flow, PAR, DPoP, CIBA

**Priority:** LOW - Advanced use cases

---

#### Issue #16: Dynamic Client Registration (LOW) - 3-4 days
**Why:** Self-service client registration via API

**Priority:** LOW - Future enhancement

---

#### Issue #9: Duende Feature Parity Analysis (ONGOING)
**Purpose:** Strategic planning, track feature gaps

**Priority:** ONGOING - Documentation

---

## 📊 Dependencies & Critical Path

```
Foundation (Complete) ✅
    │
    ├──> Issue #1 (Tests) ──────┐
    │                            │
    ├──> Issue #4 (Security) ────┤
    │                            ├──> Issue #3 (UAT Deploy)
    ├──> Issue #5 (Admin UI) ────┘            │
    │                                          │
    │                                          ├──> Issue #7 (Multi-Assistant Test)
    │                                          │            │
    │                                          ├──> Issue #2 (Lexipro Integration)
    │                                          │            │
    │                                          └────────────┴──> Issue #8 (Production Deploy)
    │                                                                      │
    └──────────────────────────────────────────────────────────────> Issue #6 (Azure AD)
                                                                           │
                                                                     Issue #11 (Sessions)
                                                                           │
                                                                     Issue #12 (2FA)
                                                                           │
                                                                     Issue #10 (Consent)
                                                                           │
                                                                     Issue #14 (Client CRUD)
                                                                           │
                                                                     Issue #13 (Reference Tokens)
                                                                           │
                                                                     Issue #15 (Advanced Flows)
                                                                           │
                                                                     Issue #16 (DCR)
```

**Critical Path:** #1 → #4 → #3 → #7 → #2 → #8

**Blockers:**
- #3 (UAT Deploy) blocks #7 (Multi-Assistant Testing)
- #7 blocks #2 (Lexipro Integration)
- #1, #4, #7, #2 block #8 (Production)

---

## 🎯 Success Metrics

### Pre-UAT
- [x] Core OAuth flows implemented
- [x] Admin UI functional (80%)
- [ ] 85+ tests passing (currently 77/81)
- [ ] Security hardening complete
- [ ] Code coverage ≥70%

### UAT
- [ ] Deployed to auth-uat.rivoli.ai
- [ ] All 4 AI assistants authenticate successfully
- [ ] NO authorization loops
- [ ] Lexipro.Api integration successful
- [ ] UAT environment stable

### Production
- [ ] Deployed to auth.rivoli.ai
- [ ] All AI assistants work in production
- [ ] Monitoring and alerts active
- [ ] Backups running
- [ ] Security audit passed
- [ ] Clerk migration complete

### Post-Production
- [ ] Azure AD integration live
- [ ] Session management active
- [ ] 2FA available
- [ ] User consent screens working

---

## ⚠️ Risk Management

### Critical Risks

**1. Multi-Assistant Compatibility (#7)**
- **Risk:** AI assistants may have auth loops or compatibility issues
- **Impact:** HIGH - This is the core use case
- **Mitigation:** Thorough testing in UAT, document each platform
- **Owner:** Issue #7

**2. Security Vulnerabilities (#4)**
- **Risk:** Missing security hardening could expose production
- **Impact:** CRITICAL - Could lead to breaches
- **Mitigation:** Complete #4 before UAT, security audit
- **Owner:** Issue #4

**3. Railway Deployment Issues (#3, #8)**
- **Risk:** Infrastructure problems, database migrations fail
- **Impact:** MEDIUM-HIGH - Blocks testing/production
- **Mitigation:** Practice in UAT first, document runbooks
- **Owner:** Issues #3, #8

### Medium Risks

**4. MCP Discovery Failures (#2, #7)**
- **Risk:** AI assistants may not discover auth server
- **Impact:** MEDIUM - Blocks assistant usage
- **Mitigation:** Test with all assistants, verify discovery endpoint
- **Owner:** Issues #2, #7

**5. Token Refresh Issues**
- **Risk:** Refresh tokens may not work correctly
- **Impact:** MEDIUM - Poor UX, frequent re-auth
- **Mitigation:** Integration tests for refresh flow
- **Owner:** Issue #1

### Low Risks

**6. Performance Under Load**
- **Risk:** Server may be slow with many users
- **Impact:** LOW-MEDIUM - Fixable with scaling
- **Mitigation:** Load testing, Railway auto-scaling
- **Owner:** Issue #8

**7. UI/UX Issues (#5, #14)**
- **Risk:** Admin UI may have bugs or poor UX
- **Impact:** LOW - Admin tool, fixable iteratively
- **Mitigation:** User testing, iterative improvements
- **Owner:** Issues #5, #14

---

## 📅 Timeline Summary

| Phase | Duration | Issues | Key Milestones |
|-------|----------|--------|----------------|
| **Pre-UAT** | 3-5 days | #1, #4, #5 | Tests passing, security hardened |
| **UAT** | 5-7 days | #3, #7, #2 | UAT deployed, all assistants tested |
| **Production** | 2-3 days | #8 | Production deployed, Clerk migrated |
| **Post-Production** | 2-4 weeks | #6, #11, #12, #10, #14 | Azure AD, 2FA, sessions, consent |
| **Future** | Ongoing | #13, #15, #16 | Advanced features as needed |

**Total to Production:** ~2-3 weeks
**Total to Enterprise-Ready:** ~6-8 weeks

---

## 🚦 Current Status & Next Actions

### ✅ Just Completed
- Admin UI core features (#5 - 80% done)
- User management (suspend, expire, delete)
- Audit logging
- Clean Lexipro-style design

### 🏃 In Progress
- None currently running

### 📋 Next Up (Immediate)

**This Week:**
1. **Issue #1** - Complete remaining tests (2 days)
2. **Issue #4** - Security hardening (2-3 days)

**Next Week:**
3. **Issue #3** - Deploy to Railway UAT (1 day)
4. **Issue #7** - Multi-assistant compatibility testing (3-4 days)
5. **Issue #2** - Lexipro.Api integration (2-3 days)

**Week 3:**
6. **Issue #8** - Production deployment (2-3 days)

**Post-Production:**
7. **Issue #6** - Azure AD integration (HIGH priority)
8. **Issue #11** - Session management
9. **Issue #12** - Two-factor authentication
10. **Issue #10** - User consent screens

---

## 📚 Documentation Status

- [x] README.md (setup instructions)
- [x] TESTING-REVIEW.md (test coverage analysis)
- [x] ROADMAP.md (this file)
- [ ] DEPLOYMENT.md (Railway deployment guide)
- [ ] SECURITY.md (security audit results)
- [ ] API-DOCUMENTATION.md (OAuth endpoints)
- [ ] ASSISTANT-SETUP.md (ChatGPT, Cline, Claude, Roo setup)

---

## 🎓 Lessons Learned (To Be Updated)

### What Went Well
- OpenIddict integration smooth
- ASP.NET Core Identity works great
- Railway database setup easy
- Test coverage achieved quickly

### What Could Be Improved
- Integration test environment setup complex
- Need better documentation for OAuth flows
- Should have planned security hardening earlier

### What's Next
- Focus on multi-assistant compatibility
- Prioritize security before UAT
- Document everything for operations team

---

## 📞 Support & Escalation

**For Issues/Questions:**
- GitHub Issues: https://github.com/rivoli-ai/andy-auth/issues
- Documentation: https://github.com/rivoli-ai/andy-auth

**Priority Escalation:**
- **P0 (Production Down):** Immediate
- **P1 (Security Issue):** Within 4 hours
- **P2 (Feature Bug):** Within 24 hours
- **P3 (Enhancement):** Backlog

---

**Last Updated:** 2025-11-16 (Post Admin UI completion)
**Next Review:** After UAT deployment (Issue #3)
