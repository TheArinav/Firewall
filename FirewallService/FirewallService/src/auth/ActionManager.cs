using FirewallService.DB;
using FirewallService.ipc.structs;
using FirewallService.ipc.structs.GeneralActionStructs;

namespace FirewallService.auth;

public class ActionManager(DBManager manager)
{
    public DBManager Manager = manager;
    public Response Execute(GeneralAction action)
    {
        // Delegate DB related requests to DBManager.
        if ((int)action.Subject > 6)
            return Manager.HandleRequest(action);
        throw new NotImplementedException();
    }
}