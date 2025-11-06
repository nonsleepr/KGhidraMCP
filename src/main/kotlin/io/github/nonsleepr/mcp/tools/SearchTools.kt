package io.github.nonsleepr.mcp.tools

import io.github.nonsleepr.mcp.*
import ghidra.program.model.listing.Function
import io.modelcontextprotocol.kotlin.sdk.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Register search-related MCP tools
 */
fun registerSearchTools(server: Server, context: GhidraContext) {
    
    // Tool: search_functions_by_name
    server.addTool(
        name = "search_functions_by_name",
        description = "Search for functions by name using substring matching. Returns function names and addresses.",
        inputSchema = createPaginatedInputSchema(
            additionalProperties = mapOf(
                "search_term" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Search term to match against function names (case-insensitive substring match)")
                ))
            ),
            additionalRequired = listOf("search_term")
        )
    ) { request: CallToolRequest ->
        try {
            val searchTerm = request.arguments.getRequiredStringParam("search_term")
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                searchFunctionsByName(context, searchTerm, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to search functions: ${e.message}")
        }
    }
}

// Helper functions

private fun searchFunctionsByName(context: GhidraContext, searchTerm: String, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    if (searchTerm.isEmpty()) {
        return "Search term is required"
    }
    
    val matches = mutableListOf<String>()
    for (func in program.functionManager.getFunctions(true)) {
        val name = func.name
        // Simple substring match (case-insensitive)
        if (name.lowercase().contains(searchTerm.lowercase())) {
            matches.add("${name} @ ${func.entryPoint}")
        }
    }
    
    matches.sort()
    
    if (matches.isEmpty()) {
        return "No functions matching '$searchTerm'"
    }
    
    return paginateList(matches, offset, limit)
}