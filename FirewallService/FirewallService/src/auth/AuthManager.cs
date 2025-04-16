using FirewallService.auth.structs;

namespace FirewallService.auth;
using Newtonsoft.Json;

public class AuthManager
{
    public AuthMainObject? MainObject { get; set; }
    public AuthManager()
    {
        var JSONstr = File.ReadAllText(FileManager.AuthFile);
        this.MainObject = JsonConvert.DeserializeObject<AuthMainObject>(JSONstr);
        if (this.MainObject?.Users.Length != 3) 
            return;
        
    }

    public void InitUsers()
    {
        
    }
    
    public bool Validate(AuthorizedUser requester, string action, out string message,out UserConnection? connection, params object[] args)
    {
        connection = null;
        if (action.StartsWith("login"))
        {
            var conn = MainObject.InitUserConnection(requester,args[0] as byte[] ?? throw new NullReferenceException("Key not provided"));
            message = conn==null ? "Invalid Credentials, Login denied." : "Login provided.";
            connection = conn;
            return conn != null;
        }
        message = "Action authorized!";
        return true;
    }
    
}