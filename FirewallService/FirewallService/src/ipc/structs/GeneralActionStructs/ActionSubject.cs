namespace FirewallService.ipc.structs.GeneralActionStructs;

public enum ActionSubject
{
    #region DB Entities
    Connection         = 0,
    ConnectionClass    = 1,
    Protocol           = 2,
    Rule               = 3,
    Record             = 4,
    Packet             = 5,
    #endregion
    #region Manager-Specific Entities
    EncryptedTunnelKey = 6,
    EncryptedTunnel    = 7,
    User               = 8,
    UserPermission     = 9,
    #endregion
    
}