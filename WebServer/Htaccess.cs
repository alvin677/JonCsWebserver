using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace WebServer
{
    public class HtaccessRules
    {
        public List<HtaccessRedirect> Redirects { get; } = new();
        public List<HtaccessRewrite> Rewrites { get; } = new();
        public string? ErrorDocument404 { get; set; }
        public string? ErrorDocument403 { get; set; }
        public bool DenyAll { get; set; }
        public List<(string key, string value)> Headers { get; } = new();
    }

    public class HtaccessRedirect
    {
        public Regex Pattern { get; init; } = null!;
        public string Target { get; init; } = "";
        public int StatusCode { get; init; } = 302;
    }

    public class HtaccessRewrite
    {
        public List<HtaccessRewriteCond> Conditions { get; init; } = new();
        public Regex Pattern { get; init; } = null!;
        public string Replacement { get; init; } = "";
        public bool IsLast { get; init; }       // [L] flag
        public bool IsRedirect { get; init; }       // [R] flag
        public int RedirectCode { get; init; } = 302;
    }

    public class HtaccessRewriteCond
    {
        public string TestString { get; init; } = "";
        public Regex? Pattern { get; init; }        // null if special pattern
        public string RawPattern { get; init; } = "";  // kept for special-case checks
        public bool Negate { get; init; }
        public bool IsFileExists { get; init; }        // -f
        public bool IsDirExists { get; init; }        // -d
        public bool IsFileSymlink { get; init; }       // -l
    }

    public static class HtaccessParser
    {
        private static readonly char[] _separators = { ' ', '\t' };

        public static HtaccessRules? Parse(string filePath)
        {
            if (!File.Exists(filePath)) return null;

            var rules = new HtaccessRules();
            string[] lines;
            try { lines = File.ReadAllLines(filePath); }
            catch { return null; }

            var pendingConds = new List<HtaccessRewriteCond>();

            foreach (string rawLine in lines)
            {
                string line = rawLine.Trim();

                // Skip comments and empty lines
                if (line.Length == 0 || line[0] == '#') continue;

                // Join continuation lines (ending with \)
                // Basic split on whitespace
                string[] parts = line.Split(_separators, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) continue;

                string directive = parts[0];

                switch (directive.ToUpperInvariant())
                {
                    case "REDIRECT":
                    case "REDIRECTMATCH":
                        {
                            // Redirect [status] source target
                            // RedirectMatch [status] pattern target
                            if (parts.Length < 3) break;

                            int statusCode = 302;
                            int sourceIdx = 1;

                            // Check if second arg is a status code or keyword
                            if (TryParseRedirectStatus(parts[1], out int parsedCode))
                            {
                                statusCode = parsedCode;
                                sourceIdx = 2;
                            }

                            if (parts.Length <= sourceIdx + 1) break;

                            string source = parts[sourceIdx];
                            string target = parts[sourceIdx + 1];

                            Regex pattern = directive.Equals("RedirectMatch", StringComparison.OrdinalIgnoreCase)
                                ? CompileRegex(source)
                                : CompileRegex("^" + Regex.Escape(source));

                            rules.Redirects.Add(new HtaccessRedirect
                            {
                                Pattern = pattern,
                                Target = target,
                                StatusCode = statusCode
                            });
                            break;
                        }

                    case "REWRITECOND":
                        {
                            if (parts.Length < 3) break;
                            string testString = parts[1];
                            string rawPattern = parts[2];
                            bool negate = rawPattern.StartsWith('!');
                            if (negate) rawPattern = rawPattern[1..];

                            // Handle special Apache condition patterns
                            bool isFileExists = rawPattern == "-f";
                            bool isDirExists = rawPattern == "-d";
                            bool isFileSymlink = rawPattern == "-l";

                            Regex? compiledPattern = (isFileExists || isDirExists || isFileSymlink)
                                ? null
                                : CompileRegex(rawPattern);

                            pendingConds.Add(new HtaccessRewriteCond
                            {
                                TestString = testString,
                                Pattern = compiledPattern,
                                RawPattern = rawPattern,
                                Negate = negate,
                                IsFileExists = isFileExists,
                                IsDirExists = isDirExists,
                                IsFileSymlink = isFileSymlink
                            });
                            break;
                        }

                    case "REWRITERULE":
                        {
                            if (parts.Length < 3) break;
                            string pattern = parts[1];
                            string replacement = parts[2];
                            string flags = parts.Length > 3 ? parts[3] : "";

                            bool isLast = flags.Contains("[L]", StringComparison.OrdinalIgnoreCase)
                                           || flags.Contains(",L]", StringComparison.OrdinalIgnoreCase)
                                           || flags.Contains("[L,", StringComparison.OrdinalIgnoreCase);
                            bool isRedirect = flags.Contains("[R]", StringComparison.OrdinalIgnoreCase)
                                           || flags.Contains(",R]", StringComparison.OrdinalIgnoreCase)
                                           || flags.Contains("[R,", StringComparison.OrdinalIgnoreCase)
                                           || flags.Contains("[R=", StringComparison.OrdinalIgnoreCase);

                            int redirectCode = 302;
                            var rMatch = Regex.Match(flags, @"\[R=(\d+)");
                            if (rMatch.Success) int.TryParse(rMatch.Groups[1].Value, out redirectCode);

                            rules.Rewrites.Add(new HtaccessRewrite
                            {
                                Conditions = new List<HtaccessRewriteCond>(pendingConds),
                                Pattern = CompileRegex(pattern),
                                Replacement = replacement,
                                IsLast = isLast,
                                IsRedirect = isRedirect,
                                RedirectCode = redirectCode
                            });
                            pendingConds.Clear();
                            break;
                        }

                    case "ERRORDOCUMENT":
                        {
                            if (parts.Length < 3) break;
                            if (parts[1] == "404") rules.ErrorDocument404 = parts[2];
                            if (parts[1] == "403") rules.ErrorDocument403 = parts[2];
                            break;
                        }

                    case "DENY":
                        {
                            // Deny from all
                            if (parts.Length >= 3 &&
                                parts[1].Equals("from", StringComparison.OrdinalIgnoreCase) &&
                                parts[2].Equals("all", StringComparison.OrdinalIgnoreCase))
                                rules.DenyAll = true;
                            break;
                        }

                    case "HEADER":
                        {
                            // Header set Key Value
                            if (parts.Length >= 4 &&
                                parts[1].Equals("set", StringComparison.OrdinalIgnoreCase))
                                rules.Headers.Add((parts[2], parts[3]));
                            break;
                        }

                    case "REWRITEENGINE":
                    case "OPTIONS":
                    case "ADDTYPE":
                    case "ALLOWOVERRIDE":
                        // Acknowledged but not acted on
                        break;
                }
            }

            return rules;
        }

        private static Regex CompileRegex(string pattern)
        {
            try
            {
                return new Regex(pattern,
                    RegexOptions.Compiled | RegexOptions.IgnoreCase,
                    TimeSpan.FromMilliseconds(100)); // timeout prevents ReDoS
            }
            catch
            {
                // Invalid regex — return never-matching pattern
                return new Regex("(?!)", RegexOptions.Compiled);
            }
        }

        private static bool TryParseRedirectStatus(string token, out int code)
        {
            code = token.ToUpperInvariant() switch
            {
                "PERMANENT" => 301,
                "TEMP" => 302,
                "SEEOTHER" => 303,
                "GONE" => 410,
                _ => 0
            };
            if (code != 0) return true;
            return int.TryParse(token, out code) && code is >= 300 and <= 399;
        }
    }
}