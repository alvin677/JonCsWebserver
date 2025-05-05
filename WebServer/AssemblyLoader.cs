using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Threading.Tasks;

namespace WebServer
{
    class HotReloadContext : AssemblyLoadContext
    {
        public HotReloadContext() : base(isCollectible: true) { }
    }
}