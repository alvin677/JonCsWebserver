using Newtonsoft.Json;

namespace WebServer
{
    public class Session
    {
        public static async Task<Dictionary<string,string>?> GetSess(string? id)
        {
            if (id == null)
            {
                string nid = GenerateRandomId();
                byte attempt = 0;
                while (!Startup.Sessions.ContainsKey(nid) && attempt < 5 && !File.Exists(Path.Combine(Program.config.SessionsDir, nid)))
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
                string Sess = await File.ReadAllTextAsync(Path.Combine(Program.config.SessionsDir, id));
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
            await File.WriteAllTextAsync(Path.Combine(Program.config.SessionsDir, id), JsonConvert.SerializeObject(data));
        }
        public static string GenerateRandomId(int length = 8)
        {
            Random random = new Random();
            return new string(Enumerable.Range(0, length).Select(_ => Program.config.Rand_Alphabet[random.Next(Program.config.Rand_Alphabet.Length)]).ToArray());
        }
    }
}
