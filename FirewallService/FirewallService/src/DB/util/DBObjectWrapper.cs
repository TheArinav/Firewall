using System.Text;
using FirewallService.util;
using Newtonsoft.Json;

namespace FirewallService.DB.util;

public class DbObjectWrapper : IStreamableObject<DbObjectWrapper>
{
    public List<Dictionary<string, object>> Data { get; set; } = new();
    public string ToStringStream()
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(this)));
    }
}