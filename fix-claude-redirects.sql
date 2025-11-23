-- Update claude-desktop client to add correct redirect URIs
-- First, delete the existing claude-desktop client
DELETE FROM "OpenIddictApplications" WHERE "ClientId" = 'claude-desktop';

-- Then insert a new one with the correct redirect URIs
INSERT INTO "OpenIddictApplications"
  ("Id", "ClientId", "ClientType", "ConsentType", "DisplayName", "Permissions", "RedirectUris", "PostLogoutRedirectUris", "Requirements", "ApplicationType", "JsonWebKeySet", "Settings", "ClientSecret", "ConcurrencyToken", "DisplayNames", "Properties")
SELECT
  gen_random_uuid(),
  'claude-desktop',
  'public',
  'implicit',
  'Claude Desktop',
  '["ept:authorization","ept:token","gt:authorization_code","gt:refresh_token","scp:email","scp:profile","rst:code"]',
  '["https://claude.ai/api/mcp/auth_callback","https://claude.com/api/mcp/auth_callback","http://127.0.0.1/callback","http://localhost/callback"]',
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL;
