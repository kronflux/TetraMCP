package com.tetramcp.util;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.swing.SwingUtilities;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Helper for executing Ghidra database modifications safely.
 * Handles EDT dispatch and transaction management.
 */
public class TransactionHelper {

    /**
     * Execute a read-only operation. Does not require EDT or transaction.
     */
    public static <T> T executeRead(Supplier<T> operation) {
        return operation.get();
    }

    /**
     * Execute a write operation within a Ghidra transaction on the EDT.
     *
     * @param program the program to modify
     * @param description transaction description for undo/redo
     * @param operation the operation to execute
     * @return the result of the operation
     * @throws RuntimeException if the operation fails
     */
    public static <T> T executeWrite(Program program, String description, Supplier<T> operation) {
        if (program == null) {
            throw new IllegalStateException("No program available for write operation");
        }

        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Throwable> error = new AtomicReference<>();

        Runnable task = () -> {
            int txId = program.startTransaction(description);
            boolean success = false;
            try {
                result.set(operation.get());
                success = true;
            }
            catch (Throwable t) {
                error.set(t);
            }
            finally {
                program.endTransaction(txId, success);
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            task.run();
        }
        else {
            try {
                SwingUtilities.invokeAndWait(task);
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to execute on EDT: " + e.getMessage(), e);
            }
        }

        if (error.get() != null) {
            Throwable t = error.get();
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            }
            throw new RuntimeException(t);
        }

        return result.get();
    }

    /**
     * Execute a write operation that returns void.
     */
    public static void executeWriteVoid(Program program, String description, Runnable operation) {
        executeWrite(program, description, () -> {
            operation.run();
            return null;
        });
    }
}
