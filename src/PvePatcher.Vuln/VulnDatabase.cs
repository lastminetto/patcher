using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace PvePatcher.Vuln;

/// <summary>Acesso ao SQLite próprio (vuln.db): cria o esquema na primeira abertura.</summary>
public sealed class VulnDatabase
{
    private const string Schema = """
        CREATE TABLE IF NOT EXISTS osv_range(
            ecosystem TEXT NOT NULL,
            pkg TEXT NOT NULL,
            vuln_id TEXT NOT NULL,
            introduced TEXT,
            fixed TEXT,
            last_affected TEXT,
            severity TEXT);
        CREATE INDEX IF NOT EXISTS ix_osv_range_pkg ON osv_range(ecosystem, pkg);
        CREATE INDEX IF NOT EXISTS ix_osv_range_vuln ON osv_range(vuln_id);
        CREATE TABLE IF NOT EXISTS osv_vuln(
            vuln_id TEXT PRIMARY KEY,
            is_advisory INTEGER NOT NULL,
            summary TEXT,
            cvss_vector TEXT,
            cvss_score REAL) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS osv_alias(
            vuln_id TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            PRIMARY KEY(vuln_id, cve_id)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS kev(cve_id TEXT PRIMARY KEY) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS epss(cve_id TEXT PRIMARY KEY, score REAL NOT NULL) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS nvd_cache(
            cve_id TEXT PRIMARY KEY,
            cvss REAL,
            vector TEXT,
            version TEXT,
            fetched_at TEXT NOT NULL) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS feed_state(
            name TEXT PRIMARY KEY,
            updated_at TEXT,
            records INTEGER NOT NULL DEFAULT 0,
            last_error TEXT) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS http_cache(
            url TEXT PRIMARY KEY,
            etag TEXT,
            last_modified TEXT) WITHOUT ROWID;
        """;

    private readonly string _connectionString;
    private readonly string _path;
    private readonly object _lock = new();
    private bool _initialized;

    public VulnDatabase(IOptions<VulnOptions> options)
    {
        _path = options.Value.DatabasePath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _path,
            Pooling = false,
            DefaultTimeout = 60,
        }.ToString();
    }

    /// <summary>Abre uma conexão nova (o chamador descarta).</summary>
    public SqliteConnection Open()
    {
        EnsureInitialized();
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    private void EnsureInitialized()
    {
        if (_initialized) return;
        lock (_lock)
        {
            if (_initialized) return;
            var dir = Path.GetDirectoryName(Path.GetFullPath(_path));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using (var pragma = conn.CreateCommand())
            {
                pragma.CommandText = "PRAGMA journal_mode=WAL;";
                pragma.ExecuteNonQuery();
            }
            using var cmd = conn.CreateCommand();
            cmd.CommandText = Schema;
            cmd.ExecuteNonQuery();
            _initialized = true;
        }
    }

    internal static void Exec(SqliteConnection conn, string sql, SqliteTransaction? tx = null, params (string Name, object? Value)[] args)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (name, value) in args) cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    internal static long Scalar(SqliteConnection conn, string sql, params (string Name, object? Value)[] args)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in args) cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return Convert.ToInt64(cmd.ExecuteScalar() ?? 0L);
    }
}
