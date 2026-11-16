using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DreaminGeek.Siem.Data.Migrations
{
    /// <inheritdoc />
    public partial class IntegrationPacks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PackHash",
                table: "Dashboards",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PackId",
                table: "Dashboards",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PackItem",
                table: "Dashboards",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PackHash",
                table: "AlertRules",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PackId",
                table: "AlertRules",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PackItem",
                table: "AlertRules",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "InstalledPacks",
                columns: table => new
                {
                    PackId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    InstalledAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_InstalledPacks", x => x.PackId);
                });

            migrationBuilder.CreateTable(
                name: "TenantPacks",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    PackId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Token = table.Column<string>(type: "text", nullable: true),
                    EnabledAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TenantPacks", x => new { x.TenantId, x.PackId });
                    table.ForeignKey(
                        name: "FK_TenantPacks_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Dashboards_PackId_PackItem",
                table: "Dashboards",
                columns: new[] { "PackId", "PackItem" });

            migrationBuilder.CreateIndex(
                name: "IX_AlertRules_PackId_PackItem",
                table: "AlertRules",
                columns: new[] { "PackId", "PackItem" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "InstalledPacks");

            migrationBuilder.DropTable(
                name: "TenantPacks");

            migrationBuilder.DropIndex(
                name: "IX_Dashboards_PackId_PackItem",
                table: "Dashboards");

            migrationBuilder.DropIndex(
                name: "IX_AlertRules_PackId_PackItem",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "PackHash",
                table: "Dashboards");

            migrationBuilder.DropColumn(
                name: "PackId",
                table: "Dashboards");

            migrationBuilder.DropColumn(
                name: "PackItem",
                table: "Dashboards");

            migrationBuilder.DropColumn(
                name: "PackHash",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "PackId",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "PackItem",
                table: "AlertRules");
        }
    }
}
