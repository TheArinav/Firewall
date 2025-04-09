namespace FirewallService.ipc.structs.GeneralActionStructs;

public enum ActionSubject
{
    Connection      = 0 ,
    ConnectionClass = 1,
    EncryptedTunnel = 2,
    Protocol        = 3,
    Rule            = 4,
    Record          = 5,
    User            = 6,
    UserPermission  = 7
}