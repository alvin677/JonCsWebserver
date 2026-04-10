using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Diagnostics.CodeAnalysis;

namespace WebServer
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
    public class Session
    {
        static Random random = Random.Shared;
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
        public static async Task<Dictionary<string,string>?> GetSess(string? id)
        {
            if (id == null)
            {
                byte attempt = 0;
                string nid = GenerateRandomId();
                while (!Startup.Sessions.ContainsKey(nid) && attempt < 5 && !File.Exists(Path.Combine(Startup.config.SessionsDir, nid)))
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
                    Dictionary<string,string> ob = new Dictionary<string, string>();
                    ob["id"] = nid;
                    Startup.Sessions[nid] = ob;
                    return ob;
                }
                return null;
            }
            if (Startup.Sessions.TryGetValue(id, out Dictionary<string,string>? gg)) return gg;
            try
            {
                string Sess = await File.ReadAllTextAsync(Path.Combine(Startup.config.SessionsDir, id));
                gg = JsonConvert.DeserializeObject<Dictionary<string,string>>(Sess);
                if (gg != null) Startup.Sessions[id] = gg;
                return gg;
            }
            catch (Exception)
            {
                return null;
            }
        }
        public static async Task SaveSess(string id, Dictionary<string,string> data)
        {
            await File.WriteAllTextAsync(Path.Combine(Startup.config.SessionsDir, id), JsonConvert.SerializeObject(data));
        }
        public static string GenerateRandomId(int length = 8)
        {
            return new string(Enumerable.Range(0, length).Select(_ => Startup.config.Rand_Alphabet[random.Next(Startup.config.Rand_Alphabet.Length)]).ToArray());
        }
    }
}
