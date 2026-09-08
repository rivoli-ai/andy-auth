using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Andy.Auth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddUserLoginHistoryIndex : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_PerformedById_Id",
                table: "AuditLogs",
                columns: new[] { "PerformedById", "Id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AuditLogs_PerformedById_Id",
                table: "AuditLogs");
        }
    }
}
