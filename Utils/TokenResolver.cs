using dnlib.DotNet;

namespace dnSpy.Extension.MalwareMCP.Utils;

/// <summary>
/// Resolves metadata tokens to human-readable names.
/// Useful for resolving operands in IL instructions.
/// </summary>
static class TokenResolver
{
    /// <summary>Resolve a metadata token (0x06000001 etc.) to its definition</summary>
    public static string? ResolveToken(ModuleDef module, uint token)
    {
        var mdToken = new MDToken(token);
        return mdToken.Table switch
        {
            Table.TypeDef => module.ResolveTypeDef(mdToken.Rid)?.FullName,
            Table.TypeRef => module.ResolveTypeRef(mdToken.Rid)?.FullName,
            Table.Method => module.ResolveMethod(mdToken.Rid)?.FullName,
            Table.Field => module.ResolveField(mdToken.Rid)?.FullName,
            Table.MemberRef => module.ResolveMemberRef(mdToken.Rid)?.FullName,
            Table.TypeSpec => module.ResolveTypeSpec(mdToken.Rid)?.FullName,
            Table.MethodSpec => module.ResolveMethodSpec(mdToken.Rid)?.FullName,
            Table.StandAloneSig => $"StandAloneSig(0x{token:X8})",
            _ => $"Unknown(0x{token:X8})",
        };
    }

    /// <summary>Format a metadata token for display</summary>
    public static string FormatToken(IMDTokenProvider? provider)
    {
        if (provider == null) return "null";
        return $"0x{provider.MDToken.Raw:X8}";
    }

    /// <summary>Get table name from token</summary>
    public static string GetTableName(uint token)
    {
        return new MDToken(token).Table.ToString();
    }
}
