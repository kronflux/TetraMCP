package com.tetramcp.tools.patching;

import static com.tetramcp.tools.ToolBehaviour.WRITES;

import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * MCP tool for assembling instructions and patching the program. Preview mode
 * (apply=false) returns the assembled bytes without modifying the program;
 * apply=true patches the listing at the address.
 */
public class AssemblerToolProvider extends AbstractToolProvider {

    public AssemblerToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(WRITES, 
            Tool.builder().name("memory_assemble")
                .description("Assemble an instruction at an address. With apply=false (default) returns " +
                    "the assembled bytes without modifying the program (preview). With apply=true, patches " +
                    "the program at the address. For multiple instructions, separate them with newlines " +
                    "(apply mode only).")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string",
                        "description", "Address to assemble at (e.g. '0x00401000')"),
                    "assembly", Map.of("type", "string",
                        "description", "Assembly instruction(s), e.g. 'MOV EAX, 1'. Newline-separated for multiple (apply mode)."),
                    "apply", Map.of("type", "boolean",
                        "description", "Patch the program (default false = preview bytes only)"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)")
                ), List.of("address", "assembly"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                return handleAssemble(program, addr,
                    getRequiredString(request, "assembly"),
                    getOptionalBoolean(request, "apply", false));
            }
        );
    }

    private CallToolResult handleAssemble(Program program, Address addr, String assembly,
            boolean apply) {
        Assembler assembler = Assemblers.getAssembler(program);

        if (!apply) {
            byte[] bytes;
            try {
                bytes = assembler.assembleLine(addr, assembly.strip());
            }
            catch (AssemblySyntaxException e) {
                throw new IllegalArgumentException("Assembly syntax error in '" + assembly +
                    "': " + e.getMessage());
            }
            catch (AssemblySemanticException e) {
                throw new IllegalArgumentException("Assembly not valid at " + addr + " for '" +
                    assembly + "': " + e.getMessage());
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x ", b & 0xFF));
            }
            return textResult("Assembled '" + assembly.strip() + "' @ " + addr + " (" +
                bytes.length + " bytes): " + hex.toString().strip() +
                "\nRe-run with apply=true to patch the program.");
        }

        String[] lines = assembly.split("\\r?\\n");
        int count = TransactionHelper.executeWrite(program, "Assemble/patch", () -> {
            try {
                InstructionIterator it = assembler.assemble(addr, lines);
                int n = 0;
                while (it.hasNext()) {
                    Instruction insn = it.next();
                    if (insn != null) {
                        n++;
                    }
                }
                return n;
            }
            catch (AssemblySyntaxException | AssemblySemanticException
                    | MemoryAccessException | AddressOverflowException e) {
                throw new RuntimeException("Assembly failed at " + addr + ": " + e.getMessage(), e);
            }
        });
        return textResult("Patched " + count + " instruction(s) at " + addr + ".");
    }
}
