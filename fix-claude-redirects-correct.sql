-- Fix claude-desktop OAuth client redirect URIs in Railway UAT
-- This updates the existing client with the correct redirect URIs

UPDATE "OpenIddictApplications"
SET "RedirectUris" = '["https://claude.ai/api/mcp/auth_callback","https://claude.com/api/mcp/auth_callback","http://127.0.0.1/callback","http://localhost/callback"]'
WHERE "ClientId" = 'claude-desktop';

-- Verify the update
SELECT "ClientId", "RedirectUris", "ClientType", "Permissions"
FROM "OpenIddictApplications"
WHERE "ClientId" = 'claude-desktop';
