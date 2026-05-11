using Microsoft.AspNetCore.Http;
using System.Text.Json;
using System.Diagnostics.CodeAnalysis;

namespace WebServer
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
    public class Session
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = false,
            PropertyNameCaseInsensitive = true // matches Newtonsoft's default behavior
        };
        public static async Task<Dictionary<string, JsonElement>?> GetSess(HttpContext context)
        {
            _ = context.Request.Cookies.TryGetValue(Startup.config.SessionCookieName, out string? sessID);
            if (sessID == "") sessID = null;
            Dictionary<string, JsonElement>? session = await GetSess(sessID);
            if (session == null)
            {
                return session;
            }
            sessID = session["id"].GetString();
            context.Response.Headers.SetCookie = Startup.config.SessionCookieName + "=" + sessID + "; Secure; Httponly; Path=/; SameSite=Lax; Expires=" + DateTime.UtcNow.AddDays(30);
            return session;
        }
        public static async Task<Dictionary<string, JsonElement>?> GetSess(string? id)
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
                    Dictionary<string, JsonElement> ob = new Dictionary<string, JsonElement>();
                    ob["id"] = JsonSerializer.SerializeToElement(nid);
                    Startup.Sessions[nid] = ob;
                    return ob;
                }
                return null;
            }
            if (Startup.Sessions.TryGetValue(id, out Dictionary<string, JsonElement>? gg)) return gg;
            try
            {
                string Sess = await File.ReadAllTextAsync(Path.Combine(Startup.config.SessionsDir, id));
                gg = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Sess, JsonOpts);
                if (gg != null) Startup.Sessions[id] = gg;
                return gg;
            }
            catch (Exception)
            {
                return null;
            }
        }
        public static async Task SaveSess(string id, Dictionary<string, JsonElement> data)
        {
            await File.WriteAllTextAsync(Path.Combine(Startup.config.SessionsDir, id), JsonSerializer.Serialize(data, JsonOpts));
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
}
