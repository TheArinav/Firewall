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
        if (this.MainObject.Users.Length != 0) 
            return;
        Logger.CreateLock(404,3);
        Logger.Warn("No users found in auth file; No users can login. Would you like to add one?", 404);
        ReadStart:
        var resp = Logger.Read("(Y/n):", 404);
        if (resp.Equals("n", StringComparison.CurrentCultureIgnoreCase))
        {
            Logger.Warn("Proceeding without a user...");
            return;
        }
        else if (resp.Equals("y", StringComparison.CurrentCultureIgnoreCase))
        {
            Logger.CreateLock(405,2);
            Logger.RegWrite("Input user credentials", 404);
            var idS = Logger.Read("(long ID):",405);
            var pwS = Logger.Read("(string key):",405);
            var id = long.Parse(idS);
            this.MainObject = this.MainObject;
            this.MainObject.Users = [new AuthorizedUser(id, pwS, true)];

            File.WriteAllText(FileManager.AuthFile, JsonConvert.SerializeObject(this.MainObject));
            Logger.Info("User added successfully!", 405);
        }
        else
        {
            Logger.CreateLock(404,2);
            Logger.Warn("Invalid input, please try again.", 404);
            goto ReadStart;
            
        }
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