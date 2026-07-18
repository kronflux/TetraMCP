package com.tetramcp.plugin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.jobs.JobExecutor;

import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.base.project.GhidraProject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.TestTool;
import ghidra.util.Msg;

/**
 * Proves the disposal is reachable from the only place that matters - a Ghidra
 * tool running this plugin being closed.
 *
 * <p>{@code McpServerDisposeIntegrationTest} asserts that disposing a manager
 * releases what it holds. That is a different claim from this one: a plugin
 * that stopped its server and then dropped the manager without disposing it
 * would satisfy that test completely, while still leaving one sweeper thread -
 * and through it the manager, the job registry and this tool - alive per
 * open-and-close cycle, which is what a user doing ordinary work produces.
 *
 * <p>The tool is built directly rather than through {@code TestEnv}, which
 * cannot construct against a binary Ghidra install: its constructor calls
 * {@code installDefaultTool}, which needs a {@code defaultTools/CodeBrowser.tool}
 * resource that only a Ghidra source tree ships.
 *
 * <p>Nothing here asserts that the server bound its port. The plugin takes its
 * port from Ghidra Tool Options and a developer machine may already have
 * something on it, so a start here may succeed or fail - and the thread this
 * test counts is started by the manager's construction either way, which is
 * what makes the count meaningful under both outcomes.
 */
public class TetraMcpPluginDisposeIntegrationTest extends TetraMcpIntegrationTestBase {

    /**
     * Enough cycles that a per-tool leak reads as a count rather than as a
     * single thread that might have been anything.
     */
    private static final int CYCLES = 3;

    /** How long a shut-down sweeper is given to actually finish. */
    private static final long SETTLE_TIMEOUT_MS = 20_000L;

    private GhidraProject ghidraProject;

    @Before
    public void setUpProject() throws Exception {
        ghidraProject = GhidraProject.createProject(
            getTestDirectoryPath(), "TetraMcpPluginDispose", true);
    }

    @After
    public void tearDownProject() {
        if (ghidraProject != null) {
            try {
                ghidraProject.close();
            }
            catch (Exception e) {
                Msg.error(this, "Failed to close the test project", e);
            }
            ghidraProject = null;
        }
    }

    @Test
    public void closingAToolRunningThePluginLeavesNoJobSweeperBehind() throws Exception {
        assertEquals("precondition: nothing else in this JVM is running a job sweeper",
            0, awaitSweepers(0));

        for (int cycle = 0; cycle < CYCLES; cycle++) {
            PluginTool tool = openToolWithPlugin();
            assertNotNull("the tool must really be running the plugin",
                tool.getManagedPlugins().stream()
                    .filter(p -> p instanceof TetraMcpPlugin).findFirst().orElse(null));
            runSwing(tool::close);
            waitForSwing();
        }

        assertEquals(CYCLES + " open-and-close cycles of a tool running TetraMCP must "
            + "leave no job sweeper running; each one holds its whole server manager "
            + "and the tool it was built for alive", 0, awaitSweepers(0));
    }

    // --- helpers ---

    private PluginTool openToolWithPlugin() {
        return runSwing(() -> {
            PluginTool tool = new TestTool(ghidraProject.getProject());
            try {
                // The plugin requires the ProgramManager service, so its
                // provider is loaded first.
                tool.addPlugin(ProgramManagerPlugin.class.getName());
                tool.addPlugin(TetraMcpPlugin.class.getName());
            }
            catch (Exception e) {
                throw new RuntimeException("could not run TetraMCP in a Ghidra tool", e);
            }
            return tool;
        });
    }

    /** Live threads named {@link JobExecutor#SWEEPER_THREAD_NAME}. */
    private static int sweeperCount() {
        int count = 0;
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            if (JobExecutor.SWEEPER_THREAD_NAME.equals(t.getName()) && t.isAlive()) {
                count++;
            }
        }
        return count;
    }

    /**
     * The sweeper count, once it has come down to {@code expected} or the wait
     * runs out. A thread told to stop takes a moment to finish, so a count read
     * immediately after a tool closes would be timing, not evidence.
     */
    private static int awaitSweepers(int expected) throws InterruptedException {
        long deadline = System.currentTimeMillis() + SETTLE_TIMEOUT_MS;
        int count = sweeperCount();
        while (count > expected && System.currentTimeMillis() < deadline) {
            Thread.sleep(50L);
            count = sweeperCount();
        }
        return count;
    }
}
