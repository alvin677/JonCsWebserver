using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace WebServer
{
    public class Session
    {
        static async Task<JsonObject?> GetSess(string? id)
        {
            if (id == null)
            {
                string nid = GenerateRandomId();
                byte attempt = 0;
                while (!Startup.Sessions.ContainsKey(id) && attempt < 5 && !File.Exists(Path.Combine(Program.config.SessDir, id)))
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
                    JsonObject ob = new JsonObject();
                    ob.Add("id", nid);
                    Startup.Sessions[nid] = ob;
                    return ob;
                }
                return null;
            }
            if (Startup.Sessions.TryGetValue(id, out JsonObject? gg)) return gg;
            try
            {
                string Sess = await File.ReadAllTextAsync(Path.Combine(Program.config.SessDir, id));
                gg = JsonNode.Parse(Sess) as JsonObject;
                if (gg != null) Startup.Sessions[id] = gg;
                return gg;
            }
            catch (Exception)
            {
                return null;
            }
        }
        static string GenerateRandomId(int length = 8)
        {
            Random random = new Random();
            return new string(Enumerable.Range(0, length).Select(_ => Program.config.Rand_Alphabet[random.Next(Program.config.Rand_Alphabet.Length)]).ToArray());
        }
    }
}
