using Microsoft.AspNetCore.Http;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Wasmtime;

namespace WebServer
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
    public class Wasm
    {
        public class WasmContext
        {
            public HttpContext Http;
            public Memory Memory;
        }
        // public static Dictionary<string, Module> WasmModules = new Dictionary<string, Module>(StringComparer.OrdinalIgnoreCase);
        public static readonly Engine WasmEngine = new Engine();
        public static Wasmtime.Module Load(string file)
        {
            return /*WasmModules[file] =*/ Wasmtime.Module.FromFile(WasmEngine, file);
        }

        public static Linker Init(Store store)
        {
            Linker WasmLinker = new Linker(WasmEngine);
            WasmLinker.Define("env", "write",
                Function.FromCallback(store,(Caller caller, int ptr, int len) => // requires store arg
                {
                    var ctx = (WasmContext)caller.Store.GetData();
                    var span = ctx.Memory.GetSpan(ptr, len);
                    ctx.Http.Response.BodyWriter.Write(span);
                }));

            WasmLinker.Define("env", "flush",
                Function.FromCallback(store,(Caller caller) =>
                {
                    var ctx = (WasmContext)caller.Store.GetData();
                    _ = ctx.Http.Response.BodyWriter.FlushAsync();
                }));

            WasmLinker.Define("env", "complete",
                Function.FromCallback(store, (Caller caller) =>
                {
                    var ctx = (WasmContext)caller.Store.GetData();
                    _ = ctx.Http.Response.BodyWriter.CompleteAsync();
                }));

            WasmLinker.Define("env", "set_status",
                Function.FromCallback(store,(Caller caller, int code) =>
                {
                    var ctx = (WasmContext)caller.Store.GetData();
                    ctx.Http.Response.StatusCode = code;
                }));

            WasmLinker.Define("env", "set_header",
                Function.FromCallback(store, (Caller caller, int hPtr, int hLen, int vPtr, int vLen) =>
                {
                    var ctx = (WasmContext)caller.Store.GetData();

                    var headerSpan = ctx.Memory.GetSpan(hPtr,hLen);
                    var valueSpan = ctx.Memory.GetSpan(vPtr, vLen);

                    var header = Encoding.UTF8.GetString(headerSpan);
                    var value = Encoding.UTF8.GetString(valueSpan);

                    ctx.Http.Response.Headers[header] = value;
                }));
            return WasmLinker;
        }
    }
}
