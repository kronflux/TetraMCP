package com.tetramcp.tools.bookmarks;

import static com.tetramcp.tools.ToolBehaviour.READ_ONLY;
import static com.tetramcp.tools.ToolBehaviour.WRITES_IDEMPOTENT;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.tetramcp.server.McpServerManager;
import com.tetramcp.tools.AbstractToolProvider;
import com.tetramcp.util.TransactionHelper;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;

/**
 * Provides MCP tools for bookmark operations: list, create, delete, search.
 */
public class BookmarkToolProvider extends AbstractToolProvider {

    public BookmarkToolProvider(McpServerManager serverManager) {
        super(serverManager);
    }

    @Override
    protected void defineTools() {
        addTool(READ_ONLY, 
            Tool.builder().name("bookmarks_list")
                .description("List bookmarks in the program. Bookmarks are annotations that mark " +
                "interesting addresses for later review.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "type", Map.of("type", "string",
                        "description", "Filter by bookmark type (e.g., 'Note', 'Warning', 'Error', 'Info')"),
                    "category", Map.of("type", "string",
                        "description", "Filter by category"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 100)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of(), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleListBookmarks(program,
                    getOptionalString(request, "type", null),
                    getOptionalString(request, "category", null),
                    getOptionalInt(request, "limit", 100));
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("bookmarks_create")
                .description("Create a bookmark at a specific address.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address to bookmark"),
                    "type", Map.of("type", "string",
                        "description", "Bookmark type: Note, Warning, Error, Info (default: Note)"),
                    "category", Map.of("type", "string",
                        "description", "Category for the bookmark (default: 'MCP')"),
                    "comment", Map.of("type", "string",
                        "description", "Description/comment for the bookmark"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address", "comment"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String type = getOptionalString(request, "type", "Note");
                String category = getOptionalString(request, "category", "MCP");
                String comment = getRequiredString(request, "comment");
                return handleCreateBookmark(program, addr, type, category, comment);
            }
        );

        addTool(WRITES_IDEMPOTENT,
            Tool.builder().name("bookmarks_delete")
                .description("Delete bookmarks at a specific address. An address can hold "
                + "several bookmarks of the same type, and all of them are deleted.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "address", Map.of("type", "string", "description", "Address of the bookmark"),
                    "type", Map.of("type", "string",
                        "description", "Bookmark type to delete (default: all types at address)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("address"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                Address addr = parseAddress(program, request, "address");
                String type = getOptionalString(request, "type", null);
                return handleDeleteBookmark(program, addr, type);
            }
        );

        addTool(READ_ONLY, 
            Tool.builder().name("bookmarks_search")
                .description("Search bookmarks by comment text.")
                .inputSchema(new JsonSchema("object", Map.of(
                    "query", Map.of("type", "string",
                        "description", "Text to search for in bookmark comments"),
                    "limit", Map.of("type", "integer", "description", "Max results (default: 50)"),
                    "program", Map.of("type", "string", "description", "Target program (omit for active)")
                ), List.of("query"), null, null, null)).build(),
            (exchange, request) -> {
                Program program = requireProgram(request);
                return handleSearchBookmarks(program,
                    getRequiredString(request, "query"),
                    getOptionalInt(request, "limit", 50));
            }
        );
    }

    // --- Handlers ---

    private CallToolResult handleListBookmarks(Program program, String typeFilter,
            String categoryFilter, int limit) {
        BookmarkManager bm = program.getBookmarkManager();

        StringBuilder sb = new StringBuilder();
        sb.append("Bookmarks:\n");

        // List bookmark types available
        BookmarkType[] types = bm.getBookmarkTypes();
        int totalCount = 0;

        for (BookmarkType type : types) {
            if (typeFilter != null && !type.getTypeString().equalsIgnoreCase(typeFilter)) continue;

            Iterator<Bookmark> iter = bm.getBookmarksIterator(type.getTypeString());
            while (iter.hasNext() && totalCount < limit) {
                Bookmark bookmark = iter.next();

                if (categoryFilter != null &&
                        !categoryFilter.equalsIgnoreCase(bookmark.getCategory())) {
                    continue;
                }

                sb.append(String.format("  [%s/%s] %s: %s\n",
                    bookmark.getTypeString(),
                    bookmark.getCategory(),
                    bookmark.getAddress(),
                    bookmark.getComment()));
                totalCount++;
            }
        }

        if (totalCount == 0) sb.append("  (no bookmarks found)\n");
        sb.append(String.format("\n%d bookmark(s)", totalCount));

        // Show available types
        if (typeFilter == null && types.length > 0) {
            sb.append("\nAvailable types: ");
            for (int i = 0; i < types.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append(types[i].getTypeString());
            }
        }

        return textResult(sb.toString());
    }

    private CallToolResult handleCreateBookmark(Program program, Address addr,
            String type, String category, String comment) {
        TransactionHelper.executeWriteVoid(program, "Create bookmark", () -> {
            program.getBookmarkManager().setBookmark(addr, type, category, comment);
        });

        return textResult(String.format("Created %s bookmark at %s: %s", type, addr, comment));
    }

    /**
     * Removes every bookmark at the address, or every bookmark of the given
     * type there. Ghidra keys a bookmark on type and category together, so one
     * address can hold several of the same type and a type names a set rather
     * than a single record.
     *
     * <p>A call that matches nothing reports a count of zero rather than an
     * absence, so a client repeating a delete whose response it never received
     * reads the second answer as the same delete standing rather than as a
     * failure.
     */
    private CallToolResult handleDeleteBookmark(Program program, Address addr, String type) {
        BookmarkManager bm = program.getBookmarkManager();

        List<Bookmark> matching = new ArrayList<>();
        for (Bookmark b : bm.getBookmarks(addr)) {
            if (type == null || b.getTypeString().equalsIgnoreCase(type)) {
                matching.add(b);
            }
        }

        if (!matching.isEmpty()) {
            TransactionHelper.executeWriteVoid(program, "Delete bookmarks", () -> {
                for (Bookmark b : matching) {
                    bm.removeBookmark(b);
                }
            });
        }

        return textResult(String.format("Deleted %d bookmark(s) at %s", matching.size(), addr));
    }

    private CallToolResult handleSearchBookmarks(Program program, String query, int limit) {
        BookmarkManager bm = program.getBookmarkManager();
        String lowerQuery = query.toLowerCase();

        StringBuilder sb = new StringBuilder();
        sb.append("Bookmark search for '").append(query).append("':\n");

        int count = 0;
        for (BookmarkType type : bm.getBookmarkTypes()) {
            Iterator<Bookmark> iter = bm.getBookmarksIterator(type.getTypeString());
            while (iter.hasNext() && count < limit) {
                Bookmark bookmark = iter.next();
                String comment = bookmark.getComment();
                if (comment != null && comment.toLowerCase().contains(lowerQuery)) {
                    sb.append(String.format("  [%s/%s] %s: %s\n",
                        bookmark.getTypeString(),
                        bookmark.getCategory(),
                        bookmark.getAddress(),
                        comment));
                    count++;
                }
            }
        }

        if (count == 0) sb.append("  (no matches)\n");
        sb.append(String.format("\n%d result(s)", count));
        return textResult(sb.toString());
    }
}
