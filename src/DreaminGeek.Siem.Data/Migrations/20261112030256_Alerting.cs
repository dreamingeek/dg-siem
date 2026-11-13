using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DreaminGeek.Siem.Data.Migrations
{
    /// <inheritdoc />
    public partial class Alerting : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ActionsJson",
                table: "AlertRules");

            migrationBuilder.AddColumn<string>(
                name: "PsaBoardId",
                table: "Tenants",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PsaBoardName",
                table: "Tenants",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PsaClientId",
                table: "Tenants",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PsaClientName",
                table: "Tenants",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "CreateTicket",
                table: "AlertRules",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "CreatedAt",
                table: "AlertRules",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));

            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "AlertRules",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "EmailTo",
                table: "AlertRules",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastError",
                table: "AlertRules",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastFiredAt",
                table: "AlertRules",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Severity",
                table: "AlertRules",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "Trigger",
                table: "AlertRules",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "UpdatedAt",
                table: "AlertRules",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));

            migrationBuilder.AlterColumn<string>(
                name: "SuppressionKey",
                table: "AlertFirings",
                type: "text",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "text",
                oldNullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastSuppressedAt",
                table: "AlertFirings",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SampleJson",
                table: "AlertFirings",
                type: "jsonb",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "Severity",
                table: "AlertFirings",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "Status",
                table: "AlertFirings",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "SuppressedCount",
                table: "AlertFirings",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "TenantSlug",
                table: "AlertFirings",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "TicketId",
                table: "AlertFirings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TicketNumber",
                table: "AlertFirings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Title",
                table: "AlertFirings",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "WindowEnd",
                table: "AlertFirings",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "WindowStart",
                table: "AlertFirings",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));

            migrationBuilder.CreateTable(
                name: "AppSettings",
                columns: table => new
                {
                    Key = table.Column<string>(type: "text", nullable: false),
                    Value = table.Column<string>(type: "text", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppSettings", x => x.Key);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AlertRules_Name",
                table: "AlertRules",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AlertRules_TenantId",
                table: "AlertRules",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AlertFirings_AlertRuleId_SuppressionKey_FiredAt",
                table: "AlertFirings",
                columns: new[] { "AlertRuleId", "SuppressionKey", "FiredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AlertFirings_FiredAt",
                table: "AlertFirings",
                column: "FiredAt");

            migrationBuilder.AddForeignKey(
                name: "FK_AlertRules_Tenants_TenantId",
                table: "AlertRules",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AlertRules_Tenants_TenantId",
                table: "AlertRules");

            migrationBuilder.DropTable(
                name: "AppSettings");

            migrationBuilder.DropIndex(
                name: "IX_AlertRules_Name",
                table: "AlertRules");

            migrationBuilder.DropIndex(
                name: "IX_AlertRules_TenantId",
                table: "AlertRules");

            migrationBuilder.DropIndex(
                name: "IX_AlertFirings_AlertRuleId_SuppressionKey_FiredAt",
                table: "AlertFirings");

            migrationBuilder.DropIndex(
                name: "IX_AlertFirings_FiredAt",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "PsaBoardId",
                table: "Tenants");

            migrationBuilder.DropColumn(
                name: "PsaBoardName",
                table: "Tenants");

            migrationBuilder.DropColumn(
                name: "PsaClientId",
                table: "Tenants");

            migrationBuilder.DropColumn(
                name: "PsaClientName",
                table: "Tenants");

            migrationBuilder.DropColumn(
                name: "CreateTicket",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "CreatedAt",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "Description",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "EmailTo",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "LastError",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "LastFiredAt",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "Severity",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "Trigger",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "UpdatedAt",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "LastSuppressedAt",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "SampleJson",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "Severity",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "Status",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "SuppressedCount",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "TenantSlug",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "TicketId",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "TicketNumber",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "Title",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "WindowEnd",
                table: "AlertFirings");

            migrationBuilder.DropColumn(
                name: "WindowStart",
                table: "AlertFirings");

            migrationBuilder.AddColumn<string>(
                name: "ActionsJson",
                table: "AlertRules",
                type: "jsonb",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AlterColumn<string>(
                name: "SuppressionKey",
                table: "AlertFirings",
                type: "text",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "text");
        }
    }
}
