package com.tetramcp.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;

/**
 * Tolerant address parser that handles multiple input formats.
 * Accepts: "0x00401000", "00401000", "401000", decimal strings.
 */
public class AddressParser {

    /**
     * Parse an address string tolerantly.
     *
     * @param program the program providing the address factory
     * @param addressStr the address string to parse
     * @return the parsed Address, or null if invalid
     */
    public static Address parse(Program program, String addressStr) {
        if (program == null || addressStr == null || addressStr.isBlank()) {
            return null;
        }

        AddressFactory factory = program.getAddressFactory();
        String trimmed = addressStr.strip();

        // Try as-is first
        Address addr = factory.getAddress(trimmed);
        if (addr != null) {
            return addr;
        }

        // Strip 0x prefix and try
        if (trimmed.toLowerCase().startsWith("0x")) {
            addr = factory.getAddress(trimmed.substring(2));
            if (addr != null) {
                return addr;
            }
        }

        // Try adding 0x prefix (for bare hex)
        addr = factory.getAddress("0x" + trimmed);
        if (addr != null) {
            return addr;
        }

        // Try as decimal
        try {
            long value = Long.parseLong(trimmed);
            addr = factory.getDefaultAddressSpace().getAddress(value);
            if (addr != null) {
                return addr;
            }
        }
        catch (NumberFormatException e) {
            // Not a decimal number
        }

        return null;
    }
}
