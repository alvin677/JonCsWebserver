using System.Reflection;
using System.Runtime.Loader;

namespace WebServer
{
    class HotReloadContext : AssemblyLoadContext
    {
        private readonly AssemblyDependencyResolver _resolver;
//        public HotReloadContext() : base(isCollectible: true) { }

        public HotReloadContext(string mainAssemblyPath)
            : base(isCollectible: true)
        {
            _resolver = new AssemblyDependencyResolver(mainAssemblyPath);
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            // Share core assemblies with Default ALC
            if (assemblyName.Name == "WebServer")
                return AssemblyLoadContext.Default.LoadFromAssemblyName(assemblyName);

            // Resolve from deps.json or local paths
            string? path = _resolver.ResolveAssemblyToPath(assemblyName);
            if (path != null)
            {
                Console.WriteLine("Resolver found local path");
                return LoadFromAssemblyPath(path);
            }
            // Fallback: ./libs/
            string libPath = Path.Combine("libs", assemblyName.Name + ".dll");
            if (File.Exists(libPath))
            {
                Console.WriteLine("Resolver load from libs dll");
                return LoadFromAssemblyPath(Path.GetFullPath(libPath));
            }
            if (AssemblyLoadContext.Default.Assemblies.Any(asm => StringComparer.OrdinalIgnoreCase.Equals(assemblyName.Name, asm.FullName)))
            {
                Console.WriteLine("Resolver load from Default.Assemblies");
                return AssemblyLoadContext.Default.LoadFromAssemblyName(assemblyName);
            }
            // Fallback: ./deps/
            string depsPath = Path.Combine("deps", assemblyName.Name + ".dll");
            if (File.Exists(libPath))
            {
                Console.WriteLine("Resolver load from deps dll");
                return LoadFromAssemblyPath(Path.GetFullPath(libPath));
            }

            return null;
        }

        protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
        {
            string? path = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);

            if (path != null)
                return LoadUnmanagedDllFromPath(path);

            string local = Path.Combine("deps", unmanagedDllName + ".so");

            if (File.Exists(local))
                return LoadUnmanagedDllFromPath(Path.GetFullPath(local));

            return IntPtr.Zero;
        }
    }
}