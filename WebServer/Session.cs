using Microsoft.AspNetCore.Http;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebServer
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
    public class Session
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = false,
            PropertyNameCaseInsensitive = true, // matches Newtonsoft's default behavior
            TypeInfoResolver = SessionJsonContext.Default
        };
        public static async Task<Dictionary<string, string>?> GetSess(HttpContext context)
        {
            _ = context.Request.Cookies.TryGetValue(Startup.config.SessionCookieName, out string? sessID);
            if (sessID == "") sessID = null;
            Dictionary<string, string>? session = await GetSess(sessID);
            if (session == null)
            {
                return session;
            }
            sessID = session["id"];
            context.Response.Headers.SetCookie = Startup.config.SessionCookieName + "=" + sessID + "; Secure; Httponly; Path=/; SameSite=Lax; Expires=" + DateTime.UtcNow.AddDays(30);
            return session;
        }
        /// <summary>You may want to sanitize id.</summary>
        public static async Task<Dictionary<string, string>?> GetSess(string? id)
        {
            if (id == null)
            {
                byte attempt = 0;
                string nid = GenerateRandomId();
                while ((Startup.Sessions.ContainsKey(nid) || File.Exists(Path.Combine(Startup.config.SessionsDir, nid))) && attempt < 5)
                {
                    if (nid.Length > 128)
                    {
                        nid = string.Empty;
                        attempt++;
                    }
                    nid += GenerateRandomId();
                }
                if (nid != string.Empty)
                {
                    Dictionary<string, string> ob = new Dictionary<string, string>();
                    ob["id"] = /* JsonSerializer.SerializeToElement( */ nid;
                    Startup.Sessions[nid] = ob;
                    return ob;
                }
                return null;
            }
            if (Startup.Sessions.TryGetValue(id, out Dictionary<string, string>? gg)) return gg;
            try
            {
                string Sess = await File.ReadAllTextAsync(Path.Combine(Startup.config.SessionsDir, id)); // Potential improvement: embedded KV (LMDB)
                gg = JsonSerializer.Deserialize<Dictionary<string, string>>(Sess, JsonOpts); // only works for files with the right syntax
                if (gg != null) Startup.Sessions[id] = gg;
                return gg;
            }
            catch (Exception)
            {
                return null;
            }
        }
        /// <summary>Do not forget to sanitize id!</summary>
        public static async Task SaveSess(string id, Dictionary<string, string> data)
        {
            await File.WriteAllTextAsync(Path.Combine(Startup.config.SessionsDir, id), JsonSerializer.Serialize(data, JsonOpts));
        }
        public static Task SaveSessSafe(string id, Dictionary<string, string> data)
        {
            if (id == null || id.Contains(".."))
            {
                throw new ArgumentException("Invalid file path");
            }
            return SaveSess(id, data);
        }
        public static string GenerateRandomId(int length = 8)
        {
            var chars = Startup.config.Rand_Alphabet;
            return string.Create(length, chars, (span, alphabet) =>
            {
                for (int i = 0; i < span.Length; i++)
                    span[i] = alphabet[Random.Shared.Next(alphabet.Length)];
            });
        }
    }
    [System.Text.Json.Serialization.JsonSerializable(typeof(Session))]
    internal partial class SessionJsonContext : JsonSerializerContext
    {
    }
}
