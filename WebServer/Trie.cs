using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace WebServer
{
    public sealed class FileNode
    {
        public Dictionary<string, FileNode> Children = new(StringComparer.Ordinal);

        // Direct file handler
        public Func<HttpContext, string, Task>? FileHandler;

        // Directory index
        public Func<HttpContext, string, Task>? DirectoryHandler;

        // Optional optimization (avoid lambda)
        public string? IndexFileName;

        // Optional: precomputed headers
        public KeyValuePair<string, StringValues>[]? Headers;
    }
    public class Trie
    {
        public static FileNode FileRoot = new();
        public static void AddFile(string[] segments, int length, Func<HttpContext, string, Task> handler)
        {
            FileNode node = FileRoot;

            for (int i = 0; i < length; i++)
            {
                if (!node.Children.TryGetValue(segments[i], out var next))
                {
                    next = new FileNode();
                    node.Children[segments[i]] = next;
                }
                node = next;
            }

            node.FileHandler = handler;
        }
        public static void SetDirectoryIndex(string[] dirSegments, int dirLength, Func<HttpContext, string, Task> handler)
        {
            FileNode node = FileRoot;

            for (int i = 0; i < dirLength; i++)
            {
                if (!node.Children.TryGetValue(dirSegments[i], out var next))
                {
                    next = new FileNode();
                    node.Children[dirSegments[i]] = next;
                }
                node = next;
            }

            node.DirectoryHandler = handler;
        }
    }
}
