using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Andy.Auth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddCibaAuthentication : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CibaAuthentications",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    RequestHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    UserId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    Scope = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    BindingMessage = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NextPollAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    PollIntervalSeconds = table.Column<int>(type: "integer", nullable: false),
                    Status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    SessionId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ApprovedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    UsedMfa = table.Column<bool>(type: "boolean", nullable: false),
                    SecurityStampHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    NextPushAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    PushLeaseUntilUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    PushLease = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    PushDelivered = table.Column<bool>(type: "boolean", nullable: false),
                    PushAttempts = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CibaAuthentications", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CibaPushDevices",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    EndpointHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProtectedSubscription = table.Column<string>(type: "character varying(8192)", maxLength: 8192, nullable: false),
                    RegisteredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CibaPushDevices", x => x.UserId);
                    table.ForeignKey(
                        name: "FK_CibaPushDevices_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CibaAuthentications_ExpiresAtUtc",
                table: "CibaAuthentications",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_CibaAuthentications_PushDelivered_NextPushAtUtc",
                table: "CibaAuthentications",
                columns: new[] { "PushDelivered", "NextPushAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CibaAuthentications_RequestHash",
                table: "CibaAuthentications",
                column: "RequestHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CibaPushDevices_EndpointHash",
                table: "CibaPushDevices",
                column: "EndpointHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CibaAuthentications");

            migrationBuilder.DropTable(
                name: "CibaPushDevices");
        }
    }
}
