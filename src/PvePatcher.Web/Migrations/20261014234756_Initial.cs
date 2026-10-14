using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PvePatcher.Web.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Clusters",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    EndpointsJson = table.Column<string>(type: "TEXT", nullable: false),
                    Fingerprint = table.Column<string>(type: "TEXT", nullable: true),
                    LastDiscoveryAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    LastDiscoveryError = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Clusters", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Settings",
                columns: table => new
                {
                    Key = table.Column<string>(type: "TEXT", nullable: false),
                    Value = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Settings", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "Vms",
                columns: table => new
                {
                    ClusterId = table.Column<string>(type: "TEXT", nullable: false),
                    VmId = table.Column<int>(type: "INTEGER", nullable: false),
                    Node = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    AgentResponding = table.Column<bool>(type: "INTEGER", nullable: false),
                    OsJson = table.Column<string>(type: "TEXT", nullable: true),
                    NicsJson = table.Column<string>(type: "TEXT", nullable: false),
                    Distro = table.Column<int>(type: "INTEGER", nullable: false),
                    IpOverrideMode = table.Column<int>(type: "INTEGER", nullable: false),
                    IpOverrideValue = table.Column<string>(type: "TEXT", nullable: true),
                    SshPort = table.Column<int>(type: "INTEGER", nullable: false),
                    KnownHostKey = table.Column<string>(type: "TEXT", nullable: true),
                    PendingHostKey = table.Column<string>(type: "TEXT", nullable: true),
                    State = table.Column<int>(type: "INTEGER", nullable: false),
                    LastError = table.Column<string>(type: "TEXT", nullable: true),
                    LastScanAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    ScanJson = table.Column<string>(type: "TEXT", nullable: true),
                    FindingsJson = table.Column<string>(type: "TEXT", nullable: true),
                    PendingCount = table.Column<int>(type: "INTEGER", nullable: false),
                    HeldBackCount = table.Column<int>(type: "INTEGER", nullable: false),
                    CriticalFixable = table.Column<int>(type: "INTEGER", nullable: false),
                    HighFixable = table.Column<int>(type: "INTEGER", nullable: false),
                    MediumFixable = table.Column<int>(type: "INTEGER", nullable: false),
                    LowFixable = table.Column<int>(type: "INTEGER", nullable: false),
                    KevFixable = table.Column<int>(type: "INTEGER", nullable: false),
                    UnfixedCount = table.Column<int>(type: "INTEGER", nullable: false),
                    RebootRequired = table.Column<bool>(type: "INTEGER", nullable: false),
                    LastJobLog = table.Column<string>(type: "TEXT", nullable: true),
                    LastJobAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    LastJobKind = table.Column<string>(type: "TEXT", nullable: true),
                    LastJobResult = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vms", x => new { x.ClusterId, x.VmId });
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Clusters");

            migrationBuilder.DropTable(
                name: "Settings");

            migrationBuilder.DropTable(
                name: "Vms");
        }
    }
}
