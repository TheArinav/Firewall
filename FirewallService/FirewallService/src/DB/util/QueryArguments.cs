using System.Text;
using FirewallService.util;
using Newtonsoft.Json;

namespace FirewallService.DB.util;

public struct QueryArguments : IStreamableObject<QueryArguments>
{
    // Common
    public string? WhereClause { get; set; }

    // SELECT
    public string[]? SelectColumns { get; set; }

    // INSERT
    public string[]? InsertColumns { get; set; }
    public string[]? InsertValues { get; set; }

    // UPDATE
    public Dictionary<string, string>? UpdateAssignments { get; set; }

    // Enforcer type (optional, only for ActionSubject.Enforcer)
    public int? EnforcerType { get; set; }
    
    public string ToStringStream()
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(this)));
    }
    public static QueryArguments Parse(string sStream)
    {
        var str = Encoding.UTF8.GetString(Convert.FromBase64String(sStream));
        return JsonConvert.DeserializeObject<QueryArguments>(str);
    }

    public override string ToString()
    {
        return JsonConvert.SerializeObject(this);   
    }
}