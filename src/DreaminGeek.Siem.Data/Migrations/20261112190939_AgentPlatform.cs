using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DreaminGeek.Siem.Data.Migrations
{
    /// <inheritdoc />
    public partial class AgentPlatform : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Platform",
                table: "Agents",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Platform",
                table: "Agents");
        }
    }
}
