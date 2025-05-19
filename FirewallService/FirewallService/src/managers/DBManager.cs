using System.Data;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using FirewallService.DB;
using FirewallService.DB.util;
using FirewallService.ipc.structs;
using FirewallService.ipc.structs.GeneralActionStructs;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace FirewallService.managers;

public partial class DbManager
{
    private readonly string[] _validArgs;
    private readonly AppDBContext _dbContext;

    public void Init()
    {
        _dbContext.Database.EnsureCreated();
    }
    
    public DbManager()
    {
        _dbContext = new AppDBContext();
        string[] validArg1 =
        [
            "Connection.ConnectionID",
            "Connection.IPv4Address",
            "Connection.IPv6Address",
            "Connection.Port",
            "Connection.ConnectionClassID",
            "ConnectionClass.ClassID",
            "ConnectionClass.ClassName",
            "ConnectionClass.Description",
            "EncryptedTunnelDetectionEnforcer.EnforcerID",
            "EncryptedTunnelDetectionEnforcer.MaxEntropy",
            "EncryptedTunnelIntegrityEnforcer.EnforcerID",
            "EncryptedTunnelIntegrityEnforcer.TunnelType",
            "EnforcerID.EnforcerID",
            "FirewallRule.RuleID",
            "FirewallRule.ConnectionClassID",
            "FirewallRule.ProtocolID",
            "FirewallRuleEnforcer.RuleID",
            "FirewallRuleEnforcer.EnforcerID",
            "FirewallRuleEnforcer.EnforcementOrder",
            "Packet.PacketID",
            "Packet.IPversion",
            "Packet.QoS",
            "Packet.Checksum",
            "Packet.Payload",
            "Packet.Source",
            "Packet.Destination",
            "PayloadLengthEnforcer.EnforcerID",
            "PayloadLengthEnforcer.Maximum",
            "PayloadLengthEnforcer.Minimum",
            "Protocol.ProtocolID",
            "Protocol.ProtocolName",
            "Protocol.ActiveStatus",
            "Protocol.EnforcerID",
            "RateLimitingEnforcer.EnforcerID",
            "RateLimitingEnforcer.MaxPacketsPerSecond",
            "Record.RecordID",
            "Record.Verdict",
            "Record.Timestamp",
            "Record.PacketID",
            "Record.RuleID",
            "RegexEnforcer.EnforcerID",
            "RegexEnforcer.Pattern",
            "TCPStateEnforcer.EnforcerID",
            "TCPStateEnforcer.IsEnabled",
            "TLSFingerprintEnforcer.EnforcerID",
            "TLSFingerprintEnforcer.AllowedFingerprints",
            "*"
        ];
        _validArgs = validArg1
            .Select(cur => cur.Split('.').Last().ToLower())
            .Distinct()
            .ToArray();
    }

    public Response HandleRequest(GeneralAction generalActionRequest)
    {
        var queryArgs =  QueryArguments.Parse(generalActionRequest.Arguments);
        // 1) Determine a target table (whitelisted)
        string? tableName; 
        {
            tableName = GetTableName(generalActionRequest.Subject, queryArgs, out var err);
            if (err is { } error)
                return error;
        }
        
        if (tableName == null)
            return new Response(false, "Invalid argument for Enforcer type", null, null);
        

        // 3) Build SQL + collect parameters
        var sqlBuilder = new StringBuilder();
        var parameters = new List<SqliteParameter>();

        switch (generalActionRequest.Prototype)
        {
            case ActionPrototype.Get:
                if (queryArgs.SelectColumns == null || queryArgs.SelectColumns.Length == 0)
                    return new Response(false, "Missing SelectColumns", null, null);

                if (!queryArgs.SelectColumns.All(col => _validArgs.Contains(col.ToLowerInvariant())))
                    return new Response(false, "Invalid Select column", null, null);

                sqlBuilder.Append($"SELECT {string.Join(", ", queryArgs.SelectColumns)} FROM {tableName}");

                if (!string.IsNullOrWhiteSpace(queryArgs.WhereClause))
                    AppendWhereClause(sqlBuilder, parameters, queryArgs.WhereClause);
                break;

            case ActionPrototype.Create:
            {
                // ---- 1. Basic validation ------------------------------------------------
                if (queryArgs.InsertColumns == null || queryArgs.InsertValues == null)
                    return new Response(false, "Missing insert data", null, null);

                if (queryArgs.InsertColumns.Length != queryArgs.InsertValues.Length)
                    return new Response(false, "InsertColumns and InsertValues length mismatch", null, null);

                if (!queryArgs.InsertColumns.All(col => _validArgs.Contains(col.ToLowerInvariant())))
                    return new Response(false, "Invalid insert column", null, null);

                // ---- 2. Copy to mutable lists and inject IsActive -----------------------
                var cols   = queryArgs.InsertColumns.ToList();
                var values = queryArgs.InsertValues.ToList();

                var hasIsActive =
                    cols.Any(c => string.Equals(c, "IsActive", StringComparison.OrdinalIgnoreCase));

                if (!hasIsActive)
                {
                    cols.Add("IsActive");
                    values.Add("true");          // will be written as a SQL literal later
                }
                else
                {
                    // If caller supplied IsActive, force it to TRUE regardless of what they sent
                    var idx = cols.FindIndex(c => string.Equals(c, "IsActive", StringComparison.OrdinalIgnoreCase));
                    values[idx] = "true";
                }

                // ---- 3. Build INSERT ----------------------------------------------------
                sqlBuilder.Append($"INSERT INTO {tableName} ({string.Join(", ", cols)}) VALUES (");

                for (var i = 0; i < values.Count; i++)
                {
                    // The injected literal 'true' is written directly –
                    // every other value is parameterised as before.
                    if (cols[i].Equals("IsActive", StringComparison.OrdinalIgnoreCase))
                    {
                        sqlBuilder.Append((i > 0 ? ", " : "") + "true");
                        continue;
                    }

                    var pName = $"@p{parameters.Count}";
                    parameters.Add(new SqliteParameter(pName, ConvertValue(values[i])));
                    sqlBuilder.Append((i > 0 ? ", " : "") + pName);
                }

                sqlBuilder.Append(')');
            }
            break;


            case ActionPrototype.Update:
                if (queryArgs.UpdateAssignments == null || queryArgs.UpdateAssignments.Count == 0)
                    return new Response(false, "Missing update assignments", null, null);

                if (!queryArgs.UpdateAssignments.Keys.All(k => _validArgs.Contains(k.ToLowerInvariant())))
                    return new Response(false, "Invalid update column", null, null);

                sqlBuilder.Append($"UPDATE {tableName} SET ");
                var updates = queryArgs.UpdateAssignments.Select(kvp =>
                {
                    var paramName = $"@p{parameters.Count}";
                    parameters.Add(new SqliteParameter(paramName, ConvertValue(kvp.Value)));
                    return $"{kvp.Key} = {paramName}";
                });
                sqlBuilder.Append(string.Join(", ", updates));

                if (!string.IsNullOrWhiteSpace(queryArgs.WhereClause))
                    AppendWhereClause(sqlBuilder, parameters, queryArgs.WhereClause);
                break;

            case ActionPrototype.Delete:
            case ActionPrototype.Suppress:
                if (generalActionRequest.Prototype == ActionPrototype.Delete)
                    sqlBuilder.Append($"DELETE FROM {tableName}");
                else
                    sqlBuilder.Append($"UPDATE {tableName} SET IsActive = False");

                if (!string.IsNullOrWhiteSpace(queryArgs.WhereClause))
                    AppendWhereClause(sqlBuilder, parameters, queryArgs.WhereClause);
                break;

            default:
                throw new ArgumentOutOfRangeException();
        }


        // 4) Execute safely with parameters
        var results = new DbObjectWrapper();
        try
        {
            // get the underlying SQLite connection
            var conn = (SqliteConnection)_dbContext.Database.GetDbConnection();
            if (conn.State != ConnectionState.Open)
                conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = sqlBuilder.ToString();
            cmd.Parameters.AddRange(parameters.ToArray());

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                for (var i = 0; i < reader.FieldCount; i++)
                    row[reader.GetName(i)] = reader.GetValue(i);
                results.Data.Add(row);
            }

            return new Response(true, "", [results], null);
        }
        catch (SqliteException ex)
        {
            return new Response(false, $"SQLite error: {ex.Message}", null, null);
        }
        catch (Exception ex)
        {
            return new Response(false, $"General error: {ex.Message}", null, null);
        }
    }

    public string GetAssociatedIDs(ActionSubject subject, QueryArguments args)
    {
        if (args.WhereClause is null)
            return "";
        var clause = args.WhereClause!;
        if (GetTableName(subject, args, out var _) is not { } tableName)
            return "";  // Or throw/log error? Your choice

        // Infer the primary key name conventionally: TableName + "ID"
        var primaryKey = tableName + "ID";

        if (!_validArgs.Contains(primaryKey.ToLowerInvariant()))
            return ""; // Invalid key, reject early

        if (!IsValidWhereClause(clause))
            return ""; // Invalid WHERE syntax

        var sql = new StringBuilder($"SELECT {primaryKey} FROM {tableName}");
        var parameters = new List<SqliteParameter>();

        AppendWhereClause(sql, parameters, clause);

        var resultIDs = new List<string>();

        try
        {
            var conn = (SqliteConnection)_dbContext.Database.GetDbConnection();
            if (conn.State != ConnectionState.Open)
                conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql.ToString();
            cmd.Parameters.AddRange(parameters.ToArray());

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var value = reader.GetValue(0).ToString();
                if (!string.IsNullOrEmpty(value))
                    resultIDs.Add(value);
            }

            return string.Join(",", resultIDs); // You can return as list if preferred
        }
        catch
        {
            return ""; // Swallow or log exception, based on context
        }
    }


    private static string? GetTableName(ActionSubject subject, QueryArguments args, out Response? err)
    {
        err = null;
        return subject switch
        {
            ActionSubject.Connection => "Connections",
            ActionSubject.ConnectionClass => "ConnectionClasses",
            ActionSubject.Protocol => "Protocols",
            ActionSubject.Rule => "FirewallRules",
            ActionSubject.Record => "Records",
            ActionSubject.Enforcer => ResolveEnforcerTable(args, out err),
            _ => null
        };
    }

    private static string ResolveEnforcerTable(QueryArguments arguments, out Response? error)
    {
        error = null;
        var type = arguments.EnforcerType ?? -1;
        var res =  type switch
        {
            0 => "EncryptedTunnelDetectionEnforcers",
            1 => "EncryptedTunnelIntegrityEnforcers",
            2 => "PayloadLengthEnforcers",
            3 => "RateLimitingEnforcers",
            4 => "RegexEnforcers",
            5 => "TCPStateEnforcers",
            6 => "TLSFingerprintEnforcers",
            _ => ""
        };
        error = res == "" ? new Response(false, "Invalid enforcer type", null, null) : null;
        return res;
    }

    private void AppendWhereClause(StringBuilder sql, List<SqliteParameter> parameters, string whereClause)
    {
        if (!IsValidWhereClause(whereClause))
            throw new ArgumentException("Invalid WHERE clause format.");

        // split on AND/OR, preserving the connectors
        var tokens = Regex.Split(
            whereClause,
            @"\s+(AND|OR)\s+",
            RegexOptions.IgnoreCase);

        sql.Append(" WHERE ");
        
        for (var i = 0; i < tokens.Length; i += 2)
        {
            if (i > 0)
                sql.Append($" {tokens[i - 1].ToUpperInvariant()} ");

            var cond = tokens[i];
            // parse field, op, value
            var m = MyRegex().Match(cond);

            var field = m.Groups["f"].Value;
            var op = m.Groups["o"].Value.ToUpperInvariant();
            var raw = m.Groups["v"].Value;

            var val = ConvertValue(raw);
            var pName = $"@p{parameters.Count}";
            parameters.Add(new SqliteParameter(pName, val));

            sql.Append($"{field} {op} {pName}");
        }
    }

    private static object ConvertValue(string raw)
    {
        raw = raw.Trim();
        if (raw.StartsWith("'") && raw.EndsWith("'"))
            return raw[1..^1];
        if (bool.TryParse(raw, out var b))
            return b;
        if (double.TryParse(raw, NumberStyles.Any, CultureInfo.InvariantCulture, out var d))
            return d;
        return raw; // fallback as string
    }

    private bool IsValidWhereClause(string input)
    {
        var propsPattern = string.Join("|",
            _validArgs.Select(Regex.Escape));
        const string ops = @"=|!=|<|<=|>|>=|LIKE";
        const string valPat = @"(?:'[^']*'|\d+(\.\d+)?|true|false)";

        var condPat = $@"\s*(?:{propsPattern})\s*(?:{ops})\s*{valPat}\s*";
        var fullPat = $@"^{condPat}(?:\s+(AND|OR)\s+{condPat})*$";

        return Regex.IsMatch(input, fullPat, RegexOptions.IgnoreCase);
    }

    [GeneratedRegex(@"^\s*(?<f>\w+)\s*(?<o>=|!=|<|<=|>|>=|LIKE)\s*(?<v>'.*?'|\d+(\.\d+)?|true|false)\s*$", RegexOptions.IgnoreCase, "en-GB")]
    private static partial Regex MyRegex();
}