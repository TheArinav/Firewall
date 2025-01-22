using System.Text;
using FirewallService.DB.Entities;
using FirewallService.ipc.structs;
using FirewallService.util;

namespace FirewallService.auth.structs;

public struct AuthorizedUser : IStreamableObject<AuthorizedUser>
{
    public long ID { get; set; }
    public string Key { get; set; }

    public AuthorizedUser()
    {
        this.ID = default;
        this.Key = "";
    }
    public AuthorizedUser(long ID, string Key)
    {
        this.ID = ID;
        this.Key = Key;
    }

    public string ToStringStream()
    {
        return $"({UtilityMethods.SerializeNumber(this.ID)}),'{this.Key}'";
    }

    private const string HEX_DIGITS = "0123456789ABCDEF";
    private const string LETTERS = "abcdefghijklmnopqrstuvwxyz";
    private const string DEC_DIGITS = "01233456789";
    private const string SPECIAL = "!@#$%^&*+=-_?";
    public static AuthorizedUser Parse(string sStream)
    {
        string idChars="", keyChars="";
        var index = 0;
        foreach (var c in sStream)
        {
            switch (index)
            {
                case 0 when c == '(':
                case 17 when c== ',':
                    break;
                case 0 when c != '(':
                case 17 when c!= ',':
                    goto Fail;
                default:
                {
                    if ((index == 18 || index == sStream.Length-2 ) )
                        if (c != '\'') 
                            goto Fail;
                        else break;
                    else if (index == sStream.Length-1)
                        if (c != ')') 
                            goto Fail;
                        else break;
                    else if (index is >= 1 and <= 16 && !HEX_DIGITS.Contains(c))
                        goto Fail;
                    else if(!(LETTERS.Contains((c+"").ToLower()) || DEC_DIGITS.Contains(c) || SPECIAL.Contains(c)))
                        goto Fail;
                    break;
                }
            }

            switch (index)
            {
                case >= 1 and <= 16:
                    idChars += c;
                    break;
                case > 18 when index < sStream.Length - 2:
                    keyChars += c;
                    break;
            }
            index++;
        }
        return new AuthorizedUser(UtilityMethods.DeserializeNumber(idChars).ToInt64(null), keyChars);
        Fail:
        {
            throw new FormatException($"String '{sStream}' can't be parsed to AuthorizedUser");
        }
    }
}