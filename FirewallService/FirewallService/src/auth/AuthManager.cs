﻿using FirewallService.auth.structs;

namespace FirewallService.auth;
using Newtonsoft.Json;

public class AuthManager
{
    public AuthMainObject MainObject { get; set; }
    public AuthManager()
    {
        string JSONstr = File.ReadAllText(FileManager.AuthFile);
        this.MainObject = JsonConvert.DeserializeObject<AuthMainObject>(JSONstr);
    }

    public bool Validate(AuthorizedUser requester, string action, out string message)
    {
        message = "Action authorized!";
        return true;
    }
}