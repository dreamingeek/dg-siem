using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DreaminGeek.Siem.Data.Migrations
{
    /// <inheritdoc />
    public partial class Dashboards : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "CreatedAt",
                table: "Dashboards",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));

            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "Dashboards",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RefreshSeconds",
                table: "Dashboards",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "TimeRange",
                table: "Dashboards",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_Dashboards_Name",
                table: "Dashboards",
                column: "Name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Dashboards_Name",
                table: "Dashboards");

            migrationBuilder.DropColumn(
                name: "CreatedAt",
                table: "Dashboards");

            migrationBuilder.DropColumn(
                name: "Description",
                table: "Dashboards");

            migrationBuilder.DropColumn(
                name: "RefreshSeconds",
                table: "Dashboards");

            migrationBuilder.DropColumn(
                name: "TimeRange",
                table: "Dashboards");
        }
    }
}
