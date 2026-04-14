package com.tetramcp.prompts;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.server.McpServerFeatures.SyncPromptSpecification;
import io.modelcontextprotocol.spec.McpSchema.*;

/**
 * Provides MCP Prompts - pre-built analysis prompt templates that guide AI agents
 * through common reverse engineering workflows.
 */
public class PromptProvider {

    public List<SyncPromptSpecification> getPromptSpecifications() {
        List<SyncPromptSpecification> specs = new ArrayList<>();

        specs.add(new SyncPromptSpecification(
            new Prompt("function-analysis",
                "Analyze a specific function: understand its purpose, parameters, " +
                "return value, and behavior.",
                List.of(
                    new PromptArgument("function", "Function name or address to analyze", true)
                )),
            (exchange, request) -> {
                String func = (String) request.arguments().getOrDefault("function", "main");
                return new GetPromptResult("Function Analysis", List.of(
                    new PromptMessage(Role.USER, new TextContent(String.format("""
                        Analyze the function '%s' in the open Ghidra program.

                        Steps:
                        1. Use functions_get to get basic info about the function
                        2. Use functions_decompile to get the decompiled source
                        3. Use functions_callers and functions_callees to understand context
                        4. Use xrefs_function to find all cross-references
                        5. Examine any interesting strings or constants
                        6. Rename the function and its variables with descriptive names
                        7. Add comments explaining the function's purpose

                        Provide a summary of:
                        - What the function does
                        - Its parameters and return value
                        - Key operations and side effects
                        - Security concerns if any
                        - Suggested function name if it's unnamed
                        """, func)))
                ));
            }
        ));

        specs.add(new SyncPromptSpecification(
            new Prompt("vulnerability-identification",
                "Scan the binary for potential security vulnerabilities.",
                List.of()),
            (exchange, request) -> new GetPromptResult("Vulnerability Scan", List.of(
                new PromptMessage(Role.USER, new TextContent("""
                    Perform a security vulnerability assessment of the open binary.

                    Steps:
                    1. Use program_info to understand the binary type and architecture
                    2. Use symbols_imports to identify dangerous API calls:
                       - Memory: malloc, free, realloc, memcpy, memmove, strcpy, strcat, sprintf
                       - Format: printf, fprintf, sprintf, snprintf (format string bugs)
                       - File: fopen, fread, fwrite, system, exec, popen
                       - Network: socket, connect, bind, listen, recv, send
                    3. For each dangerous import, use xrefs_to to find call sites
                    4. Decompile functions that use these dangerous APIs
                    5. Look for:
                       - Buffer overflows (unchecked sizes)
                       - Format string vulnerabilities
                       - Use-after-free patterns
                       - Integer overflows before allocation
                       - Command injection
                       - Missing bounds checks
                    6. Create bookmarks at each vulnerability with severity assessment

                    Produce a report with each finding including:
                    - Location (function and address)
                    - Vulnerability type
                    - Severity (Critical/High/Medium/Low)
                    - Description of the issue
                    - Potential exploitation scenario
                    """))
            ))
        ));

        specs.add(new SyncPromptSpecification(
            new Prompt("struct-recovery",
                "Recover a structure definition from how memory is accessed in a function.",
                List.of(
                    new PromptArgument("function", "Function that uses the structure", true)
                )),
            (exchange, request) -> {
                String func = (String) request.arguments().getOrDefault("function", "");
                return new GetPromptResult("Structure Recovery", List.of(
                    new PromptMessage(Role.USER, new TextContent(String.format("""
                        Recover the structure definition used in function '%s'.

                        Steps:
                        1. Decompile the function with functions_decompile
                        2. Look for pointer dereferences at fixed offsets (e.g., *(param + 0x10))
                        3. For each offset, determine the field type from how it's used:
                           - Compared to zero? Likely int/pointer
                           - Passed to string functions? Likely char*
                           - Used as array index? Likely int/size_t
                           - Dereferenced as pointer? Likely pointer to another struct
                        4. Check callers to see how the struct is allocated (reveals total size)
                        5. Use structs_create to define the recovered structure
                        6. Apply it with data_set_type at relevant addresses
                        7. Retype the function parameter to use the struct pointer

                        Provide the recovered C struct definition with field names and comments.
                        """, func)))
                ));
            }
        ));

        specs.add(new SyncPromptSpecification(
            new Prompt("binary-triage",
                "Perform initial triage of a binary: what is it, what does it do, " +
                "what's interesting about it.",
                List.of()),
            (exchange, request) -> new GetPromptResult("Binary Triage", List.of(
                new PromptMessage(Role.USER, new TextContent("""
                    Perform initial triage of the open binary.

                    Steps:
                    1. Use program_info for basic metadata (format, arch, compiler)
                    2. Use memory_list_segments to understand memory layout
                    3. Use data_list_strings with common filters:
                       - Error messages, URLs, file paths, registry keys
                       - Crypto constants, API keys, passwords
                       - Debug strings, version info
                    4. Use symbols_imports to catalog external dependencies
                    5. Use symbols_exports to see what the binary exposes
                    6. Use functions_count for analysis coverage statistics
                    7. Examine the entry point and main function
                    8. Look for interesting patterns in imports:
                       - Networking (socket, HTTP, DNS)
                       - Crypto (AES, RSA, hash functions)
                       - Anti-debug (IsDebuggerPresent, ptrace)
                       - Persistence (registry, services, scheduled tasks)

                    Produce a triage report covering:
                    - Binary type and purpose hypothesis
                    - Key capabilities identified
                    - Interesting strings and imports
                    - Recommended areas for deeper analysis
                    - Risk/threat assessment if applicable
                    """))
            ))
        ));

        specs.add(new SyncPromptSpecification(
            new Prompt("data-flow-tracing",
                "Trace how a specific value flows through the program.",
                List.of(
                    new PromptArgument("address", "Address of the instruction to trace from", true),
                    new PromptArgument("direction", "Trace direction: backward or forward", false)
                )),
            (exchange, request) -> {
                String addr = (String) request.arguments().getOrDefault("address", "");
                String dir = (String) request.arguments().getOrDefault("direction", "backward");
                return new GetPromptResult("Data Flow Trace", List.of(
                    new PromptMessage(Role.USER, new TextContent(String.format("""
                        Trace the data flow %s from address %s.

                        Steps:
                        1. Use analysis_dataflow to get the initial data flow trace
                        2. For each step in the trace, determine what operation is performed
                        3. Follow the flow across function boundaries using xrefs
                        4. Identify the ultimate source (backward) or sink (forward) of the data
                        5. Map the complete data flow path with function names and operations
                        6. Add comments at each significant point in the flow

                        Produce a data flow diagram showing:
                        - Source of the data
                        - Each transformation applied
                        - Functions the data passes through
                        - Final destination/use of the data
                        - Any sanitization or validation applied
                        """, dir, addr)))
                ));
            }
        ));

        specs.add(new SyncPromptSpecification(
            new Prompt("malware-analysis",
                "Analyze a potentially malicious binary for indicators of compromise " +
                "and malicious behavior.",
                List.of()),
            (exchange, request) -> new GetPromptResult("Malware Analysis", List.of(
                new PromptMessage(Role.USER, new TextContent("""
                    Analyze this binary for malicious behavior and indicators of compromise.

                    Steps:
                    1. Use program_info and data_list_strings for initial recon
                    2. Check imports for suspicious APIs:
                       - Process: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory
                       - Registry: RegSetValueEx, RegCreateKey
                       - Network: InternetOpenUrl, URLDownloadToFile, WinHttpOpen
                       - Evasion: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess
                       - Injection: LoadLibrary, GetProcAddress, NtCreateSection
                    3. Search for encoded/encrypted strings (XOR patterns, Base64)
                    4. Use memory_search_bytes for common shellcode patterns
                    5. Identify C2 communication patterns
                    6. Map the execution flow from entry point
                    7. Identify persistence mechanisms
                    8. Extract IOCs (IPs, URLs, mutexes, file paths, registry keys)

                    Produce a malware analysis report with:
                    - Classification (trojan, ransomware, backdoor, etc.)
                    - Capabilities identified
                    - C2 infrastructure
                    - Persistence mechanisms
                    - Evasion techniques
                    - IOCs for detection
                    - MITRE ATT&CK technique mapping
                    """))
            ))
        ));

        specs.add(new SyncPromptSpecification(
            new Prompt("deobfuscation",
                "Analyze and deobfuscate obfuscated code in the binary.",
                List.of(
                    new PromptArgument("function", "Function to deobfuscate", false)
                )),
            (exchange, request) -> {
                String func = (String) request.arguments().getOrDefault("function", "");
                String target = func.isEmpty() ? "the binary" : "function '" + func + "'";
                return new GetPromptResult("Deobfuscation", List.of(
                    new PromptMessage(Role.USER, new TextContent(String.format("""
                        Analyze and deobfuscate %s.

                        Steps:
                        1. Decompile the target and identify obfuscation patterns:
                           - Control flow flattening (switch/case state machines)
                           - Opaque predicates (always-true/false conditions)
                           - String encryption (XOR, RC4, custom)
                           - Dead code insertion
                           - Instruction substitution
                        2. For string decryption:
                           - Find the decryption function by looking for XOR loops
                           - Identify encrypted strings (high entropy data)
                           - Trace the key derivation
                        3. For control flow flattening:
                           - Identify the dispatcher variable and state transitions
                           - Map the original control flow
                        4. Rename functions and variables with clear names
                        5. Add comments explaining the deobfuscated logic
                        6. Create bookmarks at key obfuscation points

                        Provide the deobfuscated logic in readable pseudocode.
                        """, target)))
                ));
            }
        ));

        return specs;
    }
}
