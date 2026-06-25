using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipelines;
using System.Net;
using static System.Collections.Specialized.BitVector32;

namespace WebServer
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
    public class Helpers
    {
        public static readonly HashSet<string> SkipHeaders = new(StringComparer.OrdinalIgnoreCase)
        {"Connection","Keep-Alive","Proxy-Authenticate","Proxy-Authorization","TE","Trailer","Transfer-Encoding","Upgrade","Host"};
        private static readonly HttpClient httpClient = Startup.httpClient;
        /// <summary>Proxies to a an endpoint. Sends form in request body.</summary>
        public static async Task PipeFormPost(HttpContext context, Uri targetUrl, Dictionary<string, string> form)
        {
            if (Startup.config.MaxRequestBodySize != null && context.Request.ContentLength > Startup.config.MaxRequestBodySize)
            {
                context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                return;
            }
            try
            {
                using HttpRequestMessage requestMessage = new HttpRequestMessage
                {
                    Method = HttpMethod.Post,
                    RequestUri = targetUrl,
                    Version = HttpVersion.Version30,
                    VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
                    Content = new FormUrlEncodedContent(form)
                };

                foreach (var header in context.Request.Headers)
                {
                    if (SkipHeaders.Contains(header.Key))
                        continue;
                    var values = header.Value.ToArray();
                    if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, values))
                    {
                        requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, values);
                    }
                }
                if (!requestMessage.Headers.Contains("cookie")) // patch edge-case from reusing Httpclient
                {
                    requestMessage.Headers.TryAddWithoutValidation("cookie", "");
                }

                using (HttpResponseMessage responseMessage = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted))
                {
                    context.Response.StatusCode = (int)responseMessage.StatusCode;
                    foreach (var header in responseMessage.Headers)
                    {
                        context.Response.Headers[header.Key] = header.Value.ToArray();
                    }
                    foreach (var header in responseMessage.Content.Headers)
                    {
                        context.Response.Headers[header.Key] = header.Value.ToArray();
                    }

                    // Stream the response body back to the client
                    using (var responseStream = await responseMessage.Content.ReadAsStreamAsync())
                    {
                        await Startup.WritePipe(context, responseStream);
                    }
                }
                return;
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception e)
            {
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                context.Response.Headers.Remove("Cache-Control");
                await context.Response.WriteAsync("Sorry. An error occurred.");
                Console.Error.WriteLine(e.Message);
                return;
            }
        }
    }

    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
    public class Post_Extensions
    {
        static long MaxUpload = 8L * 1024 * 1024 * 1024;   // 8 GB;
        static string UpDir = "/opt/video-up";
        static HashSet<string> allowedExt = new HashSet<string>
            { ".mkv", ".avi", ".mov", ".mp4", ".ts", ".m2ts", ".wmv",
              ".flv", ".webm", ".mpg", ".mpeg", ".m4v", ".3gp", ".ogv" };
        public Post_Extensions() { }
        public Post_Extensions(long MaxUploadFileSize, string UploadFilesDir, HashSet<string> allowedExtensions) { MaxUpload = MaxUploadFileSize; UpDir = UploadFilesDir; allowedExt = allowedExtensions; }
        /// <summary>WARN: Make sure to sanitize input if needed!</summary>
        public static async Task HandleFormData(HttpContext ctx, string UploadFilePath)
        {
            string? contentType = ctx.Request.ContentType;
            if (contentType == null || !contentType.Contains("multipart/form-data"))
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsync("Expected multipart/form-data");
                return;
            }
            // Pull boundary from Content-Type header
            string? boundary = null;
            foreach (var segment in contentType.Split(';'))
            {
                var trimmed = segment.Trim();
                if (trimmed.StartsWith("boundary=", StringComparison.OrdinalIgnoreCase))
                {
                    boundary = trimmed["boundary=".Length..].Trim('"');
                    break;
                }
            }
            if (string.IsNullOrEmpty(boundary))
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsync("Missing multipart boundary");
                return;
            }

            var reader = new MultipartReader(boundary, ctx.Request.Body);
            MultipartSection? section;

            string? uploadPath = null;
            string? originalName = null;
            long bytesWritten = 0;

            try
            {
                while ((section = await reader.ReadNextSectionAsync(ctx.RequestAborted)) != null)
                {
                    // Only care about the "file" field
                    if (!ContentDispositionHeaderValue.TryParse(
                            section.Headers?["Content-Disposition"].FirstOrDefault(), out var cd))
                        continue;
                    if (!cd.DispositionType.Equals("form-data", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (!cd.Name.Equals("file", StringComparison.OrdinalIgnoreCase))
                        continue;

                    originalName = cd.FileName.Value ?? cd.FileNameStar.Value ?? "upload";
                    string origExt = Path.GetExtension(originalName).ToLowerInvariant();
                    if (!allowedExt.Contains(origExt))
                    {
                        ctx.Response.StatusCode = 415;
                        await ctx.Response.WriteAsync($"Unsupported file type: {origExt}");
                        return;
                    }

                    uploadPath = Path.Combine(UpDir, $"{UploadFilePath}{origExt}");

                    // Write directly from network stream → disk, no /tmp, no intermediate buffer
                    await using (var fs = new FileStream(
                        uploadPath,
                        FileMode.Create,
                        FileAccess.Write,
                        FileShare.None,
                        bufferSize: 1 << 17,      // 128 KB disk write buffer — matches typical HDD block size
                        useAsync: true))
                    {
                        byte[] buf = new byte[1 << 17];
                        int read;
                        while ((read = await section.Body.ReadAsync(buf, ctx.RequestAborted)) > 0)
                        {
                            bytesWritten += read;
                            if (bytesWritten > MaxUpload)
                            {
                                ctx.Response.StatusCode = 413;
                                await ctx.Response.WriteAsync("File exceeds size limit");
                                return;   // fs disposed by using, finally block cleans up file
                            }
                            await fs.WriteAsync(buf.AsMemory(0, read), ctx.RequestAborted);
                        }
                    }
                    break; // only one file field expected
                }
            }
            catch (OperationCanceledException)
            {
                ctx.Response.StatusCode = 499;
                return;
            }
            catch (Exception ex)
            {
                ctx.Response.StatusCode = 500;
                await ctx.Response.WriteAsync($"Upload error: {ex.Message}");
                return;
            }
            finally
            {
                // Clean up partial file on any early return after path was assigned
                if (uploadPath != null && bytesWritten > 0 && ctx.Response.StatusCode != 200
                    && File.Exists(uploadPath))
                    TryDelete(uploadPath);
            }
        }
        /// <summary>Write POST data directly to destination</summary>
        public static async Task HandlePostData(HttpContext ctx, string uploadPath)
        {
            PipeReader reader = ctx.Request.BodyReader;
            long bytesWritten = 0;
            bool success = false;

            try
            {
                await using var fs = new FileStream(
                    uploadPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 1 << 17,
                    useAsync: true);

                while (true)
                {
                    ReadResult result = await reader.ReadAsync(ctx.RequestAborted);
                    ReadOnlySequence<byte> buffer = result.Buffer;

                    if (buffer.Length > 0)
                    {
                        bytesWritten += buffer.Length;
                        if (bytesWritten > MaxUpload)
                        {
                            ctx.Response.StatusCode = 413;
                            await ctx.Response.WriteAsync("File exceeds size limit");
                            return;
                        }

                        // Write each segment directly — no copy for single-segment buffers
                        foreach (ReadOnlyMemory<byte> segment in buffer)
                            await fs.WriteAsync(segment, ctx.RequestAborted);

                        reader.AdvanceTo(buffer.End);
                    }

                    if (result.IsCompleted) break;
                }

                success = true;
            }
            catch (OperationCanceledException)
            {
                ctx.Response.StatusCode = 499;
            }
            catch (Exception ex)
            {
                ctx.Response.StatusCode = 500;
                await ctx.Response.WriteAsync($"Upload error: {ex.Message}");
            }
            finally
            {
                if (!success && bytesWritten > 0 && File.Exists(uploadPath))
                    TryDelete(uploadPath);
            }
        }
        static void TryDelete(string? path)
        {
            if (!string.IsNullOrEmpty(path))
                try { File.Delete(path); } catch { }
        }
    }
}
