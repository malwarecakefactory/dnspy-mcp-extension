using ModelContextProtocol.Server;
using System.ComponentModel;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.Extension.MalwareMCP.Tools;

[McpServerToolType]
public static class MethodTools
{
    /// <summary>Decompile a type to C# using dnSpy's ILSpy engine</summary>
    [McpServerTool, Description("Decompile a type to C# source code using dnSpy's built-in decompiler")]
    public static object DecompileType(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Full type name")] string type_full_name)
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var type = module.GetTypes()
            .FirstOrDefault(t => t.FullName == type_full_name)
            ?? throw new ArgumentException($"Type not found: {type_full_name}");

        var source = bridge.DecompileType(type);
        return new { type_full_name, language = "C#", source_code = source };
    }

    /// <summary>Decompile a specific method to C#</summary>
    [McpServerTool, Description("Decompile a method to C# source code")]
    public static object DecompileMethod(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Full method name (e.g., 'Stealer.Config::Decrypt')")] string method_full_name)
    {
        var (type, method) = ResolveMethod(bridge, assembly_name, method_full_name);
        var source = bridge.DecompileMethod(method);
        return new { method_full_name = method.FullName, language = "C#", source_code = source };
    }

    /// <summary>Get CIL/IL disassembly of a method</summary>
    [McpServerTool, Description("Get raw CIL/IL instructions for a method")]
    public static object DisassembleMethod(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Full method name")] string method_full_name)
    {
        var (type, method) = ResolveMethod(bridge, assembly_name, method_full_name);

        if (!method.HasBody)
            return new { error = "Method has no body (abstract/extern/pinvoke)" };

        var body = method.Body;
        var instructions = body.Instructions.Select(i => new
        {
            offset = $"IL_{i.Offset:X4}",
            opcode = i.OpCode.Name,
            operand = FormatOperand(i),
        }).ToList();

        var locals = body.Variables?.Select(v => new
        {
            index = v.Index,
            type_name = v.Type?.FullName,
        }).ToList();

        var exception_handlers = body.ExceptionHandlers?.Select(eh => new
        {
            handler_type = eh.HandlerType.ToString(),
            try_start = $"IL_{eh.TryStart?.Offset:X4}",
            try_end = $"IL_{eh.TryEnd?.Offset:X4}",
            catch_type = eh.CatchType?.FullName,
        }).ToList();

        return new
        {
            method_full_name = method.FullName,
            code_size = body.Instructions.Count,
            max_stack = body.MaxStack,
            init_locals = body.InitLocals,
            locals,
            instructions,
            exception_handlers,
        };
    }

    /// <summary>Resolve "TypeName::MethodName" to (TypeDef, MethodDef)</summary>
    internal static (TypeDef, MethodDef) ResolveMethod(DnSpyBridge bridge, string asmName, string fullName)
    {
        var module = bridge.FindModule(asmName)
            ?? throw new ArgumentException($"Assembly not found: {asmName}");

        // Try "Type::Method" format
        var parts = fullName.Split("::", 2);
        if (parts.Length == 2)
        {
            var type = module.GetTypes().FirstOrDefault(t => t.FullName == parts[0])
                ?? throw new ArgumentException($"Type not found: {parts[0]}");
            var method = type.Methods.FirstOrDefault(m => m.Name == parts[1])
                ?? throw new ArgumentException($"Method not found: {parts[1]} in {parts[0]}");
            return (type, method);
        }

        // Try finding by full method name across all types
        foreach (var t in module.GetTypes())
            foreach (var m in t.Methods)
                if (m.FullName == fullName || m.Name == fullName)
                    return (t, m);

        throw new ArgumentException($"Method not found: {fullName}");
    }

    internal static string FormatOperand(Instruction instr)
    {
        if (instr.Operand == null) return "";
        return instr.Operand switch
        {
            IMethod m => m.FullName,
            IField f => f.FullName,
            ITypeDefOrRef t => t.FullName,
            string s => $"\"{s}\"",
            Instruction target => $"IL_{target.Offset:X4}",
            _ => instr.Operand.ToString() ?? "",
        };
    }
}
