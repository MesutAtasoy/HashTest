// See https://aka.ms/new-console-template for more information


using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;


var summary = BenchmarkRunner.Run<Test>();

[MemoryDiagnoser]

public class Test
{
    public int iterate;
    public string passwordText;
    public byte[] salt;


    [GlobalSetup]
    public void Setup()
    {
        iterate = 10000;
        passwordText = "mypassword123!";
        salt = Encoding.UTF8.GetBytes("Orc0lLdKdGe9OIhPVVu06Q==");
    }


    [Benchmark]
    public string ComputeHash()
    {
        var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);
        byte[] hash = pbkdf2.GetBytes(20);

        byte[] hashBytes = new byte[36];

        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 20);

        var passwordHash = Convert.ToBase64String(hashBytes);

        return passwordHash;
    }

    [Benchmark]
    public string ComputeConstCtor()
    {
        using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordText, salt, iterate))
        {
            return Convert.ToBase64String(rfc2898DeriveBytes.GetBytes(36));
        }
    }

    [Benchmark]
    public string ComputeHashBlockCopy()
    {
        var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);
        byte[] hash = pbkdf2.GetBytes(20);

        byte[] hashBytes = new byte[36];

        System.Buffer.BlockCopy(salt, 0, hashBytes, 0, 16);
        System.Buffer.BlockCopy(hash, 0, hashBytes, 16, 20);

        var passwordHash = Convert.ToBase64String(hashBytes);

        return passwordHash;
    }

    [Benchmark]
    public string ComputeHashStringBuilder()
    {
        var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);
        byte[] hash = pbkdf2.GetBytes(20);

        byte[] hashBytes = new byte[36];

        StringBuilder sb = new StringBuilder();

        sb.Append(Encoding.UTF8.GetString(salt, 0, 16));
        sb.Append(Encoding.UTF8.GetString(hash, 0, 20));

        var passwordHash = Convert.ToBase64String(Encoding.UTF8.GetBytes(sb.ToString()));

        return passwordHash;
    }

}


