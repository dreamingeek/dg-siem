using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DreaminGeek.Siem.Data.Migrations
{
    /// <inheritdoc />
    public partial class AlertRuleKind : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Kind",
                table: "AlertRules",
                type: "integer",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Kind",
                table: "AlertRules");
        }
    }
}
