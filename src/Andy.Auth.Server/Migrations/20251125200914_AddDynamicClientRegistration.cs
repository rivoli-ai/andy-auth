using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Andy.Auth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddDynamicClientRegistration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "InitialAccessTokens",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    TokenHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CreatedById = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    CreatedByEmail = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IsMultiUse = table.Column<bool>(type: "boolean", nullable: false),
                    MaxUses = table.Column<int>(type: "integer", nullable: true),
                    UseCount = table.Column<int>(type: "integer", nullable: false),
                    IsRevoked = table.Column<bool>(type: "boolean", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedBy = table.Column<string>(type: "text", nullable: true),
                    RevocationReason = table.Column<string>(type: "text", nullable: true),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_InitialAccessTokens", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RegistrationAccessTokens",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    ClientId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    TokenHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IsRevoked = table.Column<bool>(type: "boolean", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedBy = table.Column<string>(type: "text", nullable: true),
                    RevocationReason = table.Column<string>(type: "text", nullable: true),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RegistrationAccessTokens", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DynamicClientRegistrations",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    ClientId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    RegisteredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ClientIdIssuedAt = table.Column<long>(type: "bigint", nullable: false),
                    ClientSecretExpiresAt = table.Column<long>(type: "bigint", nullable: false),
                    InitialAccessTokenId = table.Column<int>(type: "integer", nullable: true),
                    RequiresApproval = table.Column<bool>(type: "boolean", nullable: false),
                    IsApproved = table.Column<bool>(type: "boolean", nullable: false),
                    ApprovedById = table.Column<string>(type: "text", nullable: true),
                    ApprovedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IsDisabled = table.Column<bool>(type: "boolean", nullable: false),
                    DisabledAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    DisabledBy = table.Column<string>(type: "text", nullable: true),
                    DisabledReason = table.Column<string>(type: "text", nullable: true),
                    RegisteredFromIp = table.Column<string>(type: "text", nullable: true),
                    RegisteredUserAgent = table.Column<string>(type: "text", nullable: true),
                    MetadataJson = table.Column<string>(type: "text", nullable: true),
                    RegistrationAccessTokenId = table.Column<int>(type: "integer", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DynamicClientRegistrations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DynamicClientRegistrations_InitialAccessTokens_InitialAcces~",
                        column: x => x.InitialAccessTokenId,
                        principalTable: "InitialAccessTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_DynamicClientRegistrations_RegistrationAccessTokens_Registr~",
                        column: x => x.RegistrationAccessTokenId,
                        principalTable: "RegistrationAccessTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DynamicClientRegistrations_ClientId",
                table: "DynamicClientRegistrations",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DynamicClientRegistrations_InitialAccessTokenId",
                table: "DynamicClientRegistrations",
                column: "InitialAccessTokenId");

            migrationBuilder.CreateIndex(
                name: "IX_DynamicClientRegistrations_RegistrationAccessTokenId",
                table: "DynamicClientRegistrations",
                column: "RegistrationAccessTokenId");

            migrationBuilder.CreateIndex(
                name: "IX_InitialAccessTokens_TokenHash",
                table: "InitialAccessTokens",
                column: "TokenHash");

            migrationBuilder.CreateIndex(
                name: "IX_RegistrationAccessTokens_ClientId",
                table: "RegistrationAccessTokens",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RegistrationAccessTokens_TokenHash",
                table: "RegistrationAccessTokens",
                column: "TokenHash");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DynamicClientRegistrations");

            migrationBuilder.DropTable(
                name: "InitialAccessTokens");

            migrationBuilder.DropTable(
                name: "RegistrationAccessTokens");
        }
    }
}
