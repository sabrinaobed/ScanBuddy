using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScanBuddy.Migrations
{
    /// <inheritdoc />
    public partial class AddHasVerifiedOtpToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "HasVerifiedOtp",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HasVerifiedOtp",
                table: "Users");
        }
    }
}
