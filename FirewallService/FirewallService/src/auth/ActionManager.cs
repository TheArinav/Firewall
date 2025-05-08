using System.Buffers.Text;
using System.Net;
using System.Text;
using FirewallService.DB;
using FirewallService.internal_.ephemeralDB;
using FirewallService.ipc.structs;
using FirewallService.ipc.structs.GeneralActionStructs;
using Newtonsoft.Json;

namespace FirewallService.auth;

public class ActionManager(DBManager manager)
{
    public DBManager Manager = manager;
    public Response Execute(GeneralActionRequest req)
    {
        var action = req.GetAction();
        // Delegate DB related requests to DBManager.
        if ((int)action?.Subject! > 6)
        {
            var ret =  Manager.HandleRequest(action);
            if (FileManager.AuthManager.MainObject != null)
                ret.Key = Encoding.UTF8.GetBytes(FileManager.AuthManager.MainObject.UsersConnections
                    .FirstOrDefault(user => user.User.ID == req.Requester.ID)
                    ?.Key.ToString() ?? string.Empty);
            return ret;
        }

        Response? partialResp = null;
        switch (action.Subject)
        {
            case ActionSubject.EncryptedTunnelKey:
                break;
            case ActionSubject.EncryptedTunnel:
                break;
            case ActionSubject.User:
                break;
            case ActionSubject.UserPermission:
                break;
        }

        if (partialResp is null) return new Response();
        
        var rsp = partialResp ?? default;
        rsp.Key = Encoding.UTF8.GetBytes(FileManager.AuthManager.MainObject?.UsersConnections
            .FirstOrDefault(user => user.User.ID == req.Requester.ID)
            ?.Key.ToString() ?? string.Empty);
        return rsp;
        
    }

    private Response HandleEncryptedTunnel(GeneralAction action)
    {
        switch (action.Prototype)
        {
            case ActionPrototype.Get:
            {
                (IPAddress Source, IPAddress Destination) Sides;
                ushort port;
                var userID = action.UserID;

                try
                {
                    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(action.Arguments));
                    if (decoded == "*")
                    {
                        var plainstr = JsonConvert.SerializeObject(Collections.Tunnels);
                        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(plainstr));
                        var resp = new Response(true, encoded, null, null);
                    }
                    var segments = decoded.Split(',');
                    if (segments.Length != 3)
                        throw new FormatException();
                    Sides.Source = IPAddress.Parse(segments[0]);
                    Sides.Destination = IPAddress.Parse(segments[1]);
                    port = ushort.Parse(segments[2]);

                    var tunnel = Collections.Tunnels[userID]
                        .FirstOrDefault(cur => cur.Sides == Sides && cur.PortNumber == port);
                    var msg = tunnel?.ToStringStream();
                    return new Response(msg is not null, msg ?? "An unexpected error has occured.", null, null);
                }
                catch
                {
                    // Suppress errors
                }
            }
                break;
            case ActionPrototype.Create:
                break;
            case ActionPrototype.Update:
                break;
            case ActionPrototype.Delete:
                break;
            case ActionPrototype.Suppress:
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
        return new();
    }
}