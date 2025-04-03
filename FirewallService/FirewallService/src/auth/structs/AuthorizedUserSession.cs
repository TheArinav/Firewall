using System.Text;
using FirewallService.util;

namespace FirewallService.auth.structs
{
    public class AuthorizedUserSession(long id) : IStreamableObject<AuthorizedUserSession>
    {
        public long ID { get; set; } = id;
        public SecureKey Token { get; set; } = new(false);

        public AuthorizedUserSession(long id, SecureKey token) : this(id)
        {
            this.Token = token;
        }

        public string ToStringStream()
        {
            return $"({UtilityMethods.SerializeNumber(this.ID)}),'{this.Token.ToString()}'";
        }

        private const string HEX_DIGITS = "0123456789ABCDEF";
        private const string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

        public static AuthorizedUserSession Parse(string sStream)
        {
            string idChars = "", tokenChars = "";
            var index = 0;

            foreach (var c in sStream)
            {
                switch (index)
                {
                    case 0 when c == '(':
                    case 17 when c == ',':
                        break;
                    case 0 when c != '(':
                    case 17 when c != ',':
                        goto Fail;
                    default:
                    {
                        if ((index == 18 || index == sStream.Length - 2))
                        {
                            if (c != '\'')
                                goto Fail;
                            else break;
                        }
                        else if (index == sStream.Length - 1)
                        {
                            if (c != ')')
                                goto Fail;
                            else break;
                        }
                        else if (index is >= 1 and <= 16 && !HEX_DIGITS.Contains(c))
                            goto Fail;
                        else if (index > 18 && index < sStream.Length - 2 && !BASE64_CHARS.Contains(c))
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
                        tokenChars += c;
                        break;
                }

                index++;
            }

            var id = UtilityMethods.DeserializeNumber(idChars).ToInt64(null);
            var token = new SecureKey(true);
            token.Open();
            try
            {
                // We simulate loading from base64
                var raw = Convert.FromBase64String(tokenChars);
                token.Dispose(); // reset the auto-created one
                token = new SecureKey();
                for (var i = 0; i < raw.Length; i++)
                    token[i] = raw[i];
            }
            catch
            {
                goto Fail;
            }
            token.Close();

            return new AuthorizedUserSession(id) { Token = token };

            Fail:
            throw new FormatException($"String '{sStream}' can't be parsed to AuthorizedUserSession");
        }
    }
}
