using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace WebServer
{
    internal class Extensions
    {
    }
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
}
