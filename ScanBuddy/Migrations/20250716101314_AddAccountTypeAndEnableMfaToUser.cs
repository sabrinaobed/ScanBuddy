using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScanBuddy.Migrations
{
    /// <inheritdoc />
    public partial class AddAccountTypeAndEnableMfaToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "isMfaEnabled",
                table: "Users",
                newName: "enableMFA");

            migrationBuilder.AddColumn<string>(
                name: "AccountType",
                table: "Users",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AccountType",
                table: "Users");

            migrationBuilder.RenameColumn(
                name: "enableMFA",
                table: "Users",
                newName: "isMfaEnabled");
        }
    }
}
