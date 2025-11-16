# Andy Auth - Implementation Roadmap

## Current Status: Testing & UI Enhancement Phase

### ✅ Completed (Sprint 1)
- Andy.Auth library with multi-provider support (AndyAuth, Azure AD, Clerk)
- Andy.Auth.Server with OpenIddict OAuth/OIDC implementation
- Database setup with PostgreSQL
- User authentication (login, registration, logout)
- OAuth client seeding (lexipro-api, wagram-web, claude-desktop)
- Comprehensive test suite (77/81 tests passing - 95%)
- HTTPS configuration for local development
- OpenID Discovery endpoint

### 🏃 Current Sprint (Sprint 2) - UI & Integration

#### Story #5: Admin Dashboard UI ⏳ IN PROGRESS
**Goal:** Provide authenticated users with dashboard to manage OAuth clients and users

**Tasks:**
1. ✅ Create GitHub issue #5
2. ⏳ Create admin dashboard home page
3. ⏳ Add OAuth clients listing
4. ⏳ Add users listing
5. ⏳ Add navigation and user profile menu

**Acceptance Criteria:**
- Dashboard shows system statistics
- OAuth clients can be viewed
- Users can be viewed
- Clean, responsive UI matching login page design

**Priority:** Medium (UX improvement)
**Story Points:** 5
**Estimated Time:** 1-2 days

---

#### Story #1: Complete Testing Suite ⏳ IN PROGRESS (87% complete)
**Goal:** Achieve 70%+ test coverage with all critical flows tested

**Remaining Tasks:**
1. Add AuthorizationController unit tests
2. Fix integration test environment configuration
3. Add end-to-end OAuth flow tests

**Current Status:**
- ✅ 25 tests completed (DbSeeder + AccountController)
- ⏳ 4 integration tests need environment setup
- ⏳ AuthorizationController tests pending

**Priority:** High (Quality assurance)
**Story Points:** 3 (remaining)
**Estimated Time:** 1 day

---

### 📋 Next Sprint (Sprint 3) - Integration & Deployment

#### Story #2: Lexipro.Api Integration
**Goal:** Replace Clerk with Andy.Auth in Lexipro.Api

**Tasks:**
1. Update Lexipro.Api to reference Andy.Auth library
2. Configure AndyAuth provider
3. Remove Clerk dependencies
4. Update MCP metadata
5. Test OAuth flow with Claude Desktop
6. Test ChatGPT MCP discovery
7. Test VS Code Roo integration

**Acceptance Criteria:**
- Lexipro.Api authenticates with Andy.Auth.Server
- MCP discovery works
- ChatGPT can connect
- VS Code Roo can connect
- No authorization loops

**Priority:** High (Critical path)
**Story Points:** 8
**Estimated Time:** 2-3 days

---

#### Story #3: Railway UAT Deployment
**Goal:** Deploy Andy.Auth.Server to Railway for UAT testing

**Tasks:**
1. Create Railway project
2. Add PostgreSQL database
3. Configure environment variables
4. Set up custom domain (auth-uat.rivoli.ai)
5. Run migrations and seed data
6. Test HTTPS/SSL
7. Monitor logs and performance

**Acceptance Criteria:**
- Server accessible at https://auth-uat.rivoli.ai
- Database migrations applied
- OAuth clients seeded
- OpenID Discovery working
- Health checks passing

**Priority:** Medium (UAT enabler)
**Story Points:** 5
**Estimated Time:** 1 day

---

### 🔐 Future Sprint (Sprint 4) - Security & Hardening

#### Story #4: Security Hardening
**Goal:** Production-ready security measures

**Tasks:**
1. Implement rate limiting middleware
2. Add security headers (HSTS, CSP, X-Frame-Options)
3. CSRF protection verification
4. SQL injection testing
5. Brute force protection
6. Account lockout policies
7. Audit logging

**Acceptance Criteria:**
- Rate limiting active on all endpoints
- Security headers configured
- No critical vulnerabilities
- Security audit complete

**Priority:** High (Production blocker)
**Story Points:** 8
**Estimated Time:** 3-4 days

---

## Implementation Order (Clean Path)

### Phase 1: Foundation ✅ COMPLETE
- Andy.Auth library
- Andy.Auth.Server
- Database & migrations
- Basic authentication

### Phase 2: Testing & UI ⏳ CURRENT
**Order:**
1. **Issue #5** - Admin Dashboard UI (improves dev experience)
2. **Issue #1** - Complete test suite (quality gate)

### Phase 3: Integration 📅 NEXT
**Order:**
1. **Issue #3** - Railway UAT deployment (infrastructure)
2. **Issue #2** - Lexipro.Api integration (validation)

### Phase 4: Production 🔮 FUTURE
**Order:**
1. **Issue #4** - Security hardening
2. Production deployment
3. Migration from Clerk

---

## Dependencies Graph

```
Issue #1 (Tests) ─────┐
                      │
Issue #5 (Admin UI) ──┤
                      ├──> Issue #3 (Railway) ──> Issue #2 (Lexipro) ──> Issue #4 (Security) ──> PRODUCTION
                      │
```

**Notes:**
- Issues #1 and #5 can run in parallel (current sprint)
- Issue #3 must complete before #2 (need UAT server for testing)
- Issue #4 must complete before production deployment
- All issues should be substantially complete before production cutover

---

## Success Metrics

### Sprint 2 (Current)
- [ ] Admin UI functional and usable
- [ ] 28+ tests passing for Andy.Auth.Server
- [ ] Test coverage ≥ 70%

### Sprint 3
- [ ] Lexipro.Api successfully authenticates via Andy.Auth
- [ ] All MCP clients can connect (Claude, ChatGPT, Roo)
- [ ] UAT environment stable

### Sprint 4
- [ ] Security audit passed
- [ ] Rate limiting verified
- [ ] Production deployment successful
- [ ] Clerk migration complete

---

## Risk Management

### High Risk
- **OAuth loop issues** (from previous Clerk implementation)
  - Mitigation: Comprehensive integration testing in Issue #2

- **MCP discovery failures**
  - Mitigation: Test with all MCP clients before production

### Medium Risk
- **Railway deployment issues**
  - Mitigation: Document deployment process, test thoroughly in UAT

- **Database migration complexity**
  - Mitigation: Practice migrations in UAT first

### Low Risk
- **UI/UX issues**
  - Mitigation: Iterative development, user feedback

---

## Timeline Estimate

- **Sprint 2 (Current):** 2-3 days
- **Sprint 3:** 3-4 days
- **Sprint 4:** 4-5 days

**Total to Production:** ~10-12 days (2 weeks)

---

## Next Actions

1. ✅ Complete admin dashboard UI (Issue #5)
2. ✅ Finish remaining tests (Issue #1)
3. Deploy to Railway UAT (Issue #3)
4. Test Lexipro.Api integration (Issue #2)
5. Security hardening (Issue #4)
6. Production deployment
