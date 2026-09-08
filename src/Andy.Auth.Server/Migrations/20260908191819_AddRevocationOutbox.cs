using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Andy.Auth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddRevocationOutbox : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RevocationOutbox",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    SessionId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Recipient = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NextAttemptAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LeaseUntilUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LeaseToken = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    Attempts = table.Column<int>(type: "integer", nullable: false),
                    LastError = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RevocationOutbox", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RevocationOutbox_NextAttemptAtUtc_LeaseUntilUtc",
                table: "RevocationOutbox",
                columns: new[] { "NextAttemptAtUtc", "LeaseUntilUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RevocationOutbox");
        }
    }
}
