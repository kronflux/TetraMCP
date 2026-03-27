package com.tetramcp.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * Runs an external process with a bounded wall-clock timeout.
 *
 * <p>The process stdout is drained on a dedicated daemon thread so a process that
 * blocks while producing (or withholding) output cannot hang the caller: when the
 * timeout elapses the process is force-killed, which closes the stream and unblocks
 * the reader. Callers should set {@link ProcessBuilder#redirectErrorStream(boolean)}
 * if they want stderr folded into the captured output (matching prior behavior).
 */
public final class ProcessRunner {

    private ProcessRunner() {}

    /** Captured result. {@code exitCode} is -1 when {@code timedOut} is true. */
    public record Result(int exitCode, String output, boolean timedOut) {}

    /**
     * Start {@code pb} and capture its stdout.
     *
     * @param timeoutSeconds wall-clock limit; {@code <= 0} waits indefinitely.
     */
    public static Result run(ProcessBuilder pb, int timeoutSeconds)
            throws IOException, InterruptedException {
        Process process = pb.start();
        StringBuilder out = new StringBuilder();
        Thread reader = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    out.append(line).append("\n");
                }
            }
            catch (IOException ignored) {
                // Stream closed when the process is force-killed; partial output retained.
            }
        }, "tetramcp-proc-reader");
        reader.setDaemon(true);
        reader.start();

        boolean finished;
        if (timeoutSeconds > 0) {
            finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        }
        else {
            process.waitFor();
            finished = true;
        }

        if (!finished) {
            process.destroyForcibly();
            reader.join(2000);
            return new Result(-1, out.toString(), true);
        }
        reader.join(2000);
        return new Result(process.exitValue(), out.toString(), false);
    }
}
