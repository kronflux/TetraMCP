package com.tetramcp.tools.bookmarks;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.tetramcp.TetraMcpIntegrationTestBase;
import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.ToolSpecification;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;

/**
 * Holds {@code bookmarks_delete} to the scope its arguments describe.
 *
 * <p>Ghidra keys a bookmark on type <i>and</i> category, so one address can
 * carry several bookmarks of the same type - this server writes category
 * {@code MCP}, Ghidra's own analyzers write their own, and a bookmark added
 * from the Ghidra GUI carries an empty one. A delete naming only a type
 * therefore names a set rather than a single record, and the count it reports
 * is the size of that set.
 *
 * <p>The type is the only axis the delete widens along: bookmarks of another
 * type at the same address are outside what the call named and stay.
 */
public class BookmarkToolProviderIntegrationTest extends TetraMcpIntegrationTestBase {

    private static final String ADDR = "0x400100";

    private McpServerManager manager;
    private ToolSpecification deleteSpec;
    private Address addr;

    @Before
    public void setUpManager() {
        manager = new McpServerManager(null);
        manager.programOpened(program);
        manager.programActivated(program);

        for (ToolSpecification spec : new BookmarkToolProvider(manager).getToolSpecifications()) {
            if ("bookmarks_delete".equals(spec.tool().name())) {
                deleteSpec = spec;
            }
        }
        if (deleteSpec == null) {
            throw new IllegalStateException("Tool not registered: bookmarks_delete");
        }
        addr = program.getAddressFactory().getAddress(ADDR);
    }

    @After
    public void tearDownManager() throws Exception {
        if (manager != null) {
            manager.stopServer();
        }
    }

    /**
     * Three bookmarks of one type at one address, including the empty-category
     * one that {@code BookmarkManager.getBookmark(addr, type, "")} can return,
     * so a delete that stops at the first match leaves two behind and says so
     * in its count.
     */
    @Test
    public void deleteByTypeRemovesEveryBookmarkOfThatTypeAtTheAddress() {
        seedBookmark("Note", "", "from the gui");
        seedBookmark("Note", "MCP", "from this server");
        seedBookmark("Note", "Binwalk", "from a scan");

        assertEquals("Deleted 3 bookmark(s) at " + addr,
            deleteText(Map.of("address", ADDR, "type", "Note")));
        assertEquals("", bookmarksAtAddress());
    }

    @Test
    public void deleteByTypeLeavesOtherTypesAtTheSameAddress() {
        seedBookmark("Note", "MCP", "first note");
        seedBookmark("Note", "user", "second note");
        seedBookmark("Warning", "MCP", "unrelated warning");

        assertEquals("Deleted 2 bookmark(s) at " + addr,
            deleteText(Map.of("address", ADDR, "type", "Note")));
        assertEquals("Warning/MCP/unrelated warning", bookmarksAtAddress());
    }

    @Test
    public void deleteByTypeMatchesTheTypeWithoutRegardToCase() {
        seedBookmark("Note", "MCP", "first note");
        seedBookmark("Note", "user", "second note");

        assertEquals("Deleted 2 bookmark(s) at " + addr,
            deleteText(Map.of("address", ADDR, "type", "nOtE")));
        assertEquals("", bookmarksAtAddress());
    }

    @Test
    public void deleteWithoutATypeRemovesEveryBookmarkAtTheAddress() {
        seedBookmark("Note", "MCP", "a note");
        seedBookmark("Warning", "MCP", "a warning");

        assertEquals("Deleted 2 bookmark(s) at " + addr,
            deleteText(Map.of("address", ADDR)));
        assertEquals("", bookmarksAtAddress());
    }

    /**
     * A call that matches nothing reports a count of zero rather than an
     * absence. The distinction is what lets the tool carry an idempotency
     * hint: a client repeating a delete whose response was lost reads the
     * second answer as the same delete succeeding against an address that now
     * holds none, not as its delete having failed to happen.
     */
    @Test
    public void deleteMatchingNothingReportsACountOfZero() {
        seedBookmark("Warning", "MCP", "unrelated warning");

        assertEquals("Deleted 0 bookmark(s) at " + addr,
            deleteText(Map.of("address", ADDR, "type", "Note")));
        assertEquals("Warning/MCP/unrelated warning", bookmarksAtAddress());
    }

    // --- fixture ---

    /**
     * Writes a bookmark directly, so the fixture does not depend on
     * {@code bookmarks_create}. Raw transaction use is deliberate and
     * permitted in test sources.
     */
    private void seedBookmark(String type, String category, String comment) {
        int tx = program.startTransaction("seed bookmark");
        boolean success = false;
        try {
            program.getBookmarkManager().setBookmark(addr, type, category, comment);
            success = true;
        }
        finally {
            program.endTransaction(tx, success);
        }
    }

    private String deleteText(Map<String, Object> args) {
        CallToolResult result = deleteSpec.handler().apply(null,
            new CallToolRequest("bookmarks_delete", new HashMap<>(args)));
        return ((TextContent) result.content().get(0)).text();
    }

    /** Every bookmark left at the address, ordered so the comparison is stable. */
    private String bookmarksAtAddress() {
        List<String> rendered = new ArrayList<>();
        for (Bookmark b : program.getBookmarkManager().getBookmarks(addr)) {
            rendered.add(b.getTypeString() + "/" + b.getCategory() + "/" + b.getComment());
        }
        rendered.sort(String::compareTo);
        return String.join(" ", rendered);
    }
}
