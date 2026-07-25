using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Andy.Auth.Server.Migrations
{
    /// <inheritdoc />
    public partial class SEC123_AddOAuthAuthorizationConcurrencyToken : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ConcurrencyToken",
                table: "OAuthAuthorizations",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ConcurrencyToken",
                table: "OAuthAuthorizations");
        }
    }
}
