package com.tetramcp.tools.emulation;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.AddressParser;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Provides MCP tools for P-code emulation: create emulator sessions,
 * step through code, run to breakpoints, inspect state.
 *
 * Uses {@link ghidra.app.emulator.EmulatorHelper}, deprecated-for-removal since
 * Ghidra 12.1. The working, validated implementation is retained intentionally;
 * migration to {@code ghidra.pcode.emu.PcodeEmulator} (manual program-memory
 * loading + a custom userop library for CALLOTHER) is deferred until removal is
 * scheduled. Suppress the removal warnings until then.
 */
@SuppressWarnings({"deprecation", "removal"})
public class EmulationToolProvider extends AbstractToolProvider {

    private final Map<String, EmulatorSession> sessions = new ConcurrentHashMap<>();

    public EmulationToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(WRITES, 
            Tool.builder().name("emulation_create")
                .description("Create a P-code emulator session at a function entry point. " +
                "Returns a session ID for subsequent emulation commands.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "identifier", Map.of("type", "string",
                        "description", "Function name or address to emulate"),
                    "program", Map.of("type", "string",
                        "description", "Target program (omit for active)"),
                    "skip_callother", Map.of("type", "boolean",
                        "description", "Skip unhandled CALLOTHER ops (syscalls/intrinsics) so emulation " +
                            "does not halt on them (default true). Skipped ops leave their output undefined.")
                ), List.of("identifier"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleCreate(program, getRequiredString(request, "identifier"),
                    getOptionalBoolean(request, "skip_callother", true));
            }
        );

        addTool(WRITES, 
            Tool.builder().name("emulation_step")
                .description("Step the emulator forward by one or more instructions.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "session_id", Map.of("type", "string",
                        "description", "Emulator session ID from emulation_create"),
                    "count", Map.of("type", "integer",
                        "description", "Number of instructions to step (default: 1, max: 10000)")
                ), List.of("session_id"), null, null, null)).build(),
            (exchange, request) -> {
                String sessionId = getRequiredString(request, "session_id");
                int count = getOptionalInt(request, "count", 1);
                return handleStep(sessionId, count);
            }
        );

        addTool(WRITES, 
            Tool.builder().name("emulation_run_to")
                .description("Run the emulator until it reaches a target address or hits the step limit.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "session_id", Map.of("type", "string",
                        "description", "Emulator session ID"),
                    "target_address", Map.of("type", "string",
                        "description", "Address to run to"),
                    "max_steps", Map.of("type", "integer",
                        "description", "Maximum steps before timeout (default: 100000)")
                ), List.of("session_id", "target_address"), null, null, null)).build(),
            (exchange, request) -> {
                String sessionId = getRequiredString(request, "session_id");
                String targetAddr = getRequiredString(request, "target_address");
                int maxSteps = getOptionalInt(request, "max_steps", 100000);
                return handleRunTo(sessionId, targetAddr, maxSteps);
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("emulation_get_state")
                .description("Get the current register and memory state of an emulator session.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "session_id", Map.of("type", "string",
                        "description", "Emulator session ID"),
                    "memory_address", Map.of("type", "string",
                        "description", "Optional: read memory at this address"),
                    "memory_length", Map.of("type", "integer",
                        "description", "Bytes to read from memory_address (default: 64)")
                ), List.of("session_id"), null, null, null)).build(),
            (exchange, request) -> {
                String sessionId = getRequiredString(request, "session_id");
                String memAddr = getOptionalString(request, "memory_address", null);
                int memLen = getOptionalInt(request, "memory_length", 64);
                return handleGetState(sessionId, memAddr, memLen);
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("emulation_set_register")
                .description("Set a register value in an emulator session.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "session_id", Map.of("type", "string",
                        "description", "Emulator session ID"),
                    "register", Map.of("type", "string",
                        "description", "Register name (e.g., 'EAX', 'RSP', 'R0')"),
                    "value", Map.of("type", "integer",
                        "description", "Value to set (decimal or hex with 0x prefix)")
                ), List.of("session_id", "register", "value"), null, null, null)).build(),
            (exchange, request) -> {
                String sessionId = getRequiredString(request, "session_id");
                String regName = getRequiredString(request, "register");
                long value = Long.decode(getRequiredString(request, "value"));
                return handleSetRegister(sessionId, regName, value);
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("emulation_dispose")
                .description("Destroy an emulator session and free resources.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "session_id", Map.of("type", "string",
                        "description", "Emulator session ID to dispose")
                ), List.of("session_id"), null, null, null)).build(),
            (exchange, request) -> {
                String sessionId = getRequiredString(request, "session_id");
                return handleDispose(sessionId);
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleCreate(Program program, String identifier, boolean skipCallOther) {
        Function func = resolveFunction(program, identifier);

        EmulatorHelper emu = new EmulatorHelper(program);
        String sessionId = UUID.randomUUID().toString().substring(0, 8);

        Address entry = func.getEntryPoint();
        emu.setBreakpoint(entry);
        emu.writeRegister(emu.getPCRegister(), entry.getOffset());

        // Set up a basic stack
        long stackBase = 0x7FFF0000L;
        emu.writeRegister(emu.getStackPointerRegister(), stackBase);

        AtomicInteger callOtherSkipped = new AtomicInteger();
        if (skipCallOther) {
            emu.registerDefaultCallOtherCallback(new BreakCallBack() {
                @Override
                public boolean pcodeCallback(PcodeOpRaw op) {
                    // UNVERIFIED: treat unhandled CALLOTHER as a no-op so emulation continues;
                    // the op's output varnode (if any) is left undefined.
                    callOtherSkipped.incrementAndGet();
                    return true;
                }
            });
        }

        EmulatorSession session = new EmulatorSession(emu, program, func, entry, callOtherSkipped);
        sessions.put(sessionId, session);

        StringBuilder sb = new StringBuilder();
        sb.append("Emulator session created: ").append(sessionId).append("\n");
        sb.append("Function: ").append(func.getName()).append("\n");
        sb.append("Entry Point: ").append(entry).append("\n");
        sb.append("PC: ").append(entry).append("\n");
        sb.append("Stack Pointer: 0x").append(Long.toHexString(stackBase)).append("\n");
        sb.append("Skip CALLOTHER: ").append(skipCallOther).append("\n");
        sb.append("\nUse emulation_step or emulation_run_to to execute.");

        return textResult(sb.toString());
    }

    private CallToolResult handleStep(String sessionId, int count) {
        EmulatorSession session = getSession(sessionId);
        count = Math.min(count, 10000);

        StringBuilder sb = new StringBuilder();
        sb.append("Stepping ").append(count).append(" instruction(s):\n");

        EmulatorHelper emu = session.emulator;
        int stepped = 0;

        try {
            for (int i = 0; i < count; i++) {
                boolean success = emu.step(ghidra.util.task.TaskMonitor.DUMMY);
                stepped++;

                Address pc = emu.getExecutionAddress();
                sb.append(String.format("  [%d] PC=%s", stepped, pc));

                // Show the instruction at PC
                var instr = session.program.getListing().getInstructionAt(pc);
                if (instr != null) {
                    sb.append("  ").append(instr);
                }
                sb.append("\n");

                if (!success) {
                    sb.append("  (emulation halted)\n");
                    break;
                }
            }
        }
        catch (Exception e) {
            sb.append("  Error: ").append(e.getMessage()).append("\n");
        }

        sb.append(String.format("\n%d instruction(s) executed. PC=%s",
            stepped, emu.getExecutionAddress()));

        return textResult(sb.toString());
    }

    private CallToolResult handleRunTo(String sessionId, String targetAddr, int maxSteps) {
        EmulatorSession session = getSession(sessionId);
        Address target = AddressParser.parse(session.program, targetAddr);
        if (target == null) {
            throw new IllegalArgumentException("Invalid target address: " + targetAddr);
        }

        EmulatorHelper emu = session.emulator;
        emu.setBreakpoint(target);

        int steps = 0;
        boolean reached = false;

        try {
            while (steps < maxSteps) {
                boolean success = emu.step(ghidra.util.task.TaskMonitor.DUMMY);
                steps++;

                if (emu.getExecutionAddress().equals(target)) {
                    reached = true;
                    break;
                }
                if (!success) break;
            }
        }
        catch (Exception e) {
            return textResult(String.format(
                "Emulation error after %d steps: %s\nPC=%s",
                steps, e.getMessage(), emu.getExecutionAddress()));
        }

        StringBuilder sb = new StringBuilder();
        if (reached) {
            sb.append("Reached target ").append(target).append(" after ")
                .append(steps).append(" steps.\n");
        }
        else {
            sb.append("Did NOT reach target ").append(target)
                .append(" after ").append(steps).append(" steps.\n");
            sb.append("Current PC: ").append(emu.getExecutionAddress()).append("\n");
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleGetState(String sessionId, String memAddr, int memLen) {
        EmulatorSession session = getSession(sessionId);
        EmulatorHelper emu = session.emulator;

        StringBuilder sb = new StringBuilder();
        sb.append("Emulator State (session: ").append(sessionId).append("):\n");
        sb.append("PC: ").append(emu.getExecutionAddress()).append("\n");
        sb.append("CALLOTHER skipped: ").append(session.callOtherSkipped.get()).append("\n");

        // Dump general-purpose registers
        sb.append("Registers:\n");
        for (Register reg : session.program.getLanguage().getRegisters()) {
            if (reg.isBaseRegister() && !reg.isProcessorContext() &&
                    reg.getBitLength() >= 16) {
                long val = emu.readRegister(reg).longValue();
                sb.append(String.format("  %-8s = 0x%x (%d)\n",
                    reg.getName(), val, val));
            }
        }

        // Optional memory dump
        if (memAddr != null) {
            Address addr = AddressParser.parse(session.program, memAddr);
            if (addr != null) {
                sb.append(String.format("\nMemory at %s (%d bytes):\n", addr, memLen));
                memLen = Math.min(memLen, 256);
                for (int i = 0; i < memLen; i += 16) {
                    sb.append(String.format("  %s: ", addr.add(i)));
                    StringBuilder ascii = new StringBuilder();
                    for (int j = 0; j < 16 && (i + j) < memLen; j++) {
                        byte b = emu.readMemoryByte(addr.add(i + j));
                        sb.append(String.format("%02x ", b & 0xFF));
                        ascii.append(b >= 32 && b < 127 ? (char) b : '.');
                    }
                    sb.append(" |").append(ascii).append("|\n");
                }
            }
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleSetRegister(String sessionId, String regName, long value) {
        EmulatorSession session = getSession(sessionId);
        EmulatorHelper emu = session.emulator;

        Register reg = session.program.getLanguage().getRegister(regName);
        if (reg == null) {
            throw new IllegalArgumentException(
                "Unknown register: '" + regName + "'. " +
                "Use emulation_get_state to see available registers.");
        }

        emu.writeRegister(reg, value);
        return textResult(String.format("Set %s = 0x%x (%d)", regName, value, value));
    }

    private CallToolResult handleDispose(String sessionId) {
        EmulatorSession session = sessions.remove(sessionId);
        if (session == null) {
            return textResult("Session '" + sessionId + "' not found or already disposed.");
        }
        session.emulator.dispose();
        return textResult("Emulator session '" + sessionId + "' disposed.");
    }

    // --- Helpers ---

    private EmulatorSession getSession(String sessionId) {
        EmulatorSession session = sessions.get(sessionId);
        if (session == null) {
            throw new IllegalArgumentException(
                "Emulator session '" + sessionId + "' not found. " +
                "Use emulation_create to start a new session.");
        }
        return session;
    }

    private Function resolveFunction(Program program, String nameOrAddr) {
        var fm = program.getFunctionManager();
        Address addr = AddressParser.parse(program, nameOrAddr);
        if (addr != null) {
            Function func = fm.getFunctionAt(addr);
            if (func != null) return func;
        }
        var iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equalsIgnoreCase(nameOrAddr)) return func;
        }
        throw new IllegalArgumentException("Function not found: '" + nameOrAddr + "'");
    }

    private static class EmulatorSession {
        final EmulatorHelper emulator;
        final Program program;
        final Function function;
        final Address entryPoint;
        final AtomicInteger callOtherSkipped;

        EmulatorSession(EmulatorHelper emulator, Program program,
                Function function, Address entryPoint, AtomicInteger callOtherSkipped) {
            this.emulator = emulator;
            this.program = program;
            this.function = function;
            this.entryPoint = entryPoint;
            this.callOtherSkipped = callOtherSkipped;
        }
    }
}
