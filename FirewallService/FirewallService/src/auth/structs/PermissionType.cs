namespace FirewallService.auth.structs;

using FirewallService.ipc.structs.GeneralActionStructs;
public struct PermissionType(ActionPrototype prototype, ActionSubject subject) : IEquatable<PermissionType>
{
    public readonly ActionPrototype Prototype = prototype;
    public readonly ActionSubject Subject = subject;

    public bool Equals(PermissionType other)
    {
        return Prototype == other.Prototype && Subject == other.Subject;
    }

    public override bool Equals(object? obj)
    {
        return obj is PermissionType other && Equals(other);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine((int)Prototype, (int)Subject);
    }

    public static bool operator ==(PermissionType left, PermissionType right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(PermissionType left, PermissionType right)
    {
        return !(left == right);
    }
}