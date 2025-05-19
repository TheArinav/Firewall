namespace FirewallService.ipc.structs;

public enum MessageType
{
    Unset                = 0,
    InitSessionRequest   = 1,
    CreateUserRequest    = 2,
    Response             = 3,
    GeneralActionRequest = 4
}