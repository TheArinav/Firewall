namespace FirewallService.ipc.structs.GeneralActionStructs;

public enum ActionSubject
{
    #region DB Entities
    Connection         = 0,
    ConnectionClass    = 1,
    Protocol           = 2,
    Rule               = 3,
    Record             = 4,
    Enforcer           = 5,
    Packet             = 6,
    #endregion
    #region Manager-Specific Entities
    EncryptedTunnelKey = 7,
    EncryptedTunnel    = 8,
    User               = 9,
    UserPermission     = 10
    #endregion
    
}