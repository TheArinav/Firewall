using FirewallService.DB.util;
using FirewallService.ipc;
using FirewallService.ipc.structs.GeneralActionStructs;
using FirewallService.managers.ActionAuthentication;
using FirewallService.managers.structs;

namespace FirewallService.managers;
using Newtonsoft.Json;

public class AuthManager
{
    public AuthMainObject? MainObject { get; set; }
    public static PermissionManager? PermissionManager { get; private set; }
    public AuthManager()
    {
        var JSONstr = File.ReadAllText(GeneralManager.AuthFile);
        this.MainObject = JsonConvert.DeserializeObject<AuthMainObject>(JSONstr);
        if (this.MainObject?.Users.Length != 3) 
            return;
        PermissionManager = new PermissionManager();
    }
    
    public bool Validate(AuthorizedUser requester, string action, out string message,out UserConnection? connection, params object[] args)
    {
        connection = null;
        #region Handle Login
        if (action.StartsWith("login"))
        {
            var conn = MainObject.InitUserConnection(requester,args[0] as byte[] ?? throw new NullReferenceException("Key not provided"));
            message = conn==null ? "Invalid Credentials, Login denied." : "Login provided.";
            connection = conn;
            return conn != null;
        }
        #endregion
        #region Handle General Actions

        GeneralAction? act;
        QueryArguments? qArgs;
        try
        {
            act = GeneralAction.Deserialize(action);
            qArgs = QueryArguments.Parse(act!.Arguments);
        } 
        catch (Exception e) { message = $"Can't parse action: {e.Message}"; return false; }
        var pType = new PermissionType(act.Prototype, act.Subject);
        var subjectIDs = GeneralManager.DbManager.GetAssociatedIDs(act.Subject, (QueryArguments)qArgs).Split(',');
        var needRequestRoot = false;
        foreach (var id in subjectIDs)
        {
            var cond = PermissionManager?.GetPermissionForUser(requester.ID, pType,id);
            switch (cond)
            {
                case PermissionCondition.Never:
                    message = "Permission denied.";
                    return false;
                case PermissionCondition.RequestRoot:
                    needRequestRoot = true;
                    break;
                case PermissionCondition.Always:
                case null:
                default:
                    break;
            }
        }

        if (needRequestRoot)
        {
            var msg =$"""
                      General Action : 
                      Prototype: {act.Prototype}
                      Subject: {act.Subject}
                      Arguments: 
                          {qArgs!.ToString().Replace("\n","\n\t")}

                      """;
            if (!ActionAuthenticator.ShowAuthorizationPrompt(msg, requester.ID.ToString()))
            {
                message = "Permission denied by root.";
                return false;
            }
        }
            
        #endregion

        message = "Action authorized.";
        return true;
    }
    
}