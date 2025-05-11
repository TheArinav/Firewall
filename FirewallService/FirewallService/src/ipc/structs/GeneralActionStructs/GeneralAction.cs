using System.Text;
using Newtonsoft.Json;

namespace FirewallService.ipc.structs.GeneralActionStructs;

public class GeneralAction(long userId,ActionPrototype prototype, ActionSubject subject, string[] arguments) 
{
    public required ActionPrototype Prototype { get; set; } = prototype;
    public required ActionSubject Subject { get; set; } = subject;
    public required string[] Arguments { get; set; } = arguments ?? throw new ArgumentNullException(nameof(arguments));
    public required long UserID { get; set; } = userId;

    public static string Serialize(GeneralAction generalAction)
    {
        var ret =  Convert.ToBase64String(
            Encoding.UTF8.GetBytes(
                JsonConvert.SerializeObject(generalAction)));
        return ret;
    }
    
    public static GeneralAction? Deserialize(string base64)
    {
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        var obj = JsonConvert.DeserializeObject<GeneralAction>(json);
        return obj;
    }

}