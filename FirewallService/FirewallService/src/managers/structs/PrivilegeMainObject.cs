namespace FirewallService.managers.structs;

using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;

public class PrivilegeMainObject
{
    public List<UserPrivileges> UserPrivileges { get; set; } = new();

    public static string FilePath => GeneralManager.PermissionsFile;

    /// <summary>
    /// Load the privilege data from the JSON file.
    /// </summary>
    public static PrivilegeMainObject Load()
    {
        if (!File.Exists(FilePath))
            return new PrivilegeMainObject();

        var json = File.ReadAllText(FilePath);
        return JsonConvert.DeserializeObject<PrivilegeMainObject>(json) ?? new PrivilegeMainObject();
    }

    /// <summary>
    /// Save the privilege data to the JSON file.
    /// </summary>
    public void Save()
    {
        var json = JsonConvert.SerializeObject(this, Formatting.Indented);
        File.WriteAllText(FilePath, json);
    }

    public UserPrivileges? GetPrivilegesForUser(long userId)
    {
        return UserPrivileges.Find(up => up.UserID == userId);
    }

    public void SetPrivilegesForUser(UserPrivileges newPrivileges)
    {
        var existing = UserPrivileges.FindIndex(up => up.UserID == newPrivileges.UserID);
        if (existing >= 0)
            UserPrivileges[existing] = newPrivileges;
        else
            UserPrivileges.Add(newPrivileges);
    }

    public bool RemovePrivilegesForUser(long userId)
    {
        return UserPrivileges.RemoveAll(up => up.UserID == userId) > 0;
    }
}
