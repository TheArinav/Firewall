namespace FirewallService.util;

public static class ConsoleUtils
{
    public const int PASSWORD_LENGTH = 32;
    public static char[]? TemporaryPasswordStorage;

    public static void ClearTemporaryPasswordStorage()
    {
        Array.Clear(TemporaryPasswordStorage, 0, TemporaryPasswordStorage.Length);
    }

    public static void ReadPassword()
    {
        TemporaryPasswordStorage ??= new char[PASSWORD_LENGTH];
        Array.Clear(TemporaryPasswordStorage, 0, PASSWORD_LENGTH); // ensure clean state

        Console.Write("Enter password: ");

        var index = 0;

        while (true)
        {
            var key = Console.ReadKey(true);

            if (key.Key == ConsoleKey.Enter)
                break;

            if (key.Key == ConsoleKey.Backspace)
            {
                if (index > 0)
                    index--;
            }
            else if (!char.IsControl(key.KeyChar) && index < PASSWORD_LENGTH)
            {
                TemporaryPasswordStorage[index++] = key.KeyChar;
            }
        }

        Console.WriteLine();

        // Null-terminate remaining chars to prevent garbage data
        for (var i = index; i < PASSWORD_LENGTH; i++)
            TemporaryPasswordStorage[i] = '\0';
    }
}