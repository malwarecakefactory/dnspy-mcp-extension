using ModelContextProtocol.Server;
using System.ComponentModel;

namespace dnSpy.Extension.MalwareMCP.Tools;

[McpServerToolType]
public static class StringTools
{
    /// <summary>Extract strings from the #US (user strings) heap</summary>
    [McpServerTool, Description("Extract user strings from .NET #US heap with optional filtering")]
    public static object GetStrings(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Substring filter (case-insensitive)")] string? filter = null,
        [Description("Minimum string length")] int min_length = 4,
        [Description("Max results")] int limit = 500)
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var strings = new List<object>();
        var us = module.USStream;
        if (us != null)
        {
            uint offset = 1; // skip first null entry
            while (offset < us.StreamLength)
            {
                try
                {
                    var s = us.ReadNoRid(offset);
                    if (s != null && s.Length >= min_length)
                    {
                        if (filter == null || s.Contains(filter, StringComparison.OrdinalIgnoreCase))
                        {
                            strings.Add(new
                            {
                                source = "user_strings",
                                offset = $"0x{offset:X}",
                                value = s,
                                length = s.Length,
                            });
                        }
                    }
                    // Advance offset (rough — actual US encoding is blob-encoded)
                    offset += (uint)(s?.Length * 2 ?? 2) + 3;
                }
                catch { offset++; }

                if (strings.Count >= limit) break;
            }
        }

        // Also scan literal string fields
        foreach (var type in module.GetTypes())
        {
            foreach (var field in type.Fields)
            {
                if (field.IsLiteral && field.Constant?.Value is string val && val.Length >= min_length)
                {
                    if (filter == null || val.Contains(filter, StringComparison.OrdinalIgnoreCase))
                    {
                        strings.Add(new
                        {
                            source = "literal_field",
                            declaring_type = type.FullName,
                            field_name = field.Name?.String,
                            value = val,
                            length = val.Length,
                        });
                    }
                }
                if (strings.Count >= limit) break;
            }
        }

        return new { total = strings.Count, strings };
    }
}
