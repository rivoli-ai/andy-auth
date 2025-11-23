using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Andy.Auth.Server.Migrations
{
    /// <inheritdoc />
    public partial class FixClaudeDesktopRedirectUris : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Update claude-desktop OAuth client to have correct redirect URIs for Claude.ai
            migrationBuilder.Sql(@"
                UPDATE ""OpenIddictApplications""
                SET ""RedirectUris"" = '[""https://claude.ai/api/mcp/auth_callback"",""https://claude.com/api/mcp/auth_callback"",""http://127.0.0.1/callback"",""http://localhost/callback""]'
                WHERE ""ClientId"" = 'claude-desktop';
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {

        }
    }
}
