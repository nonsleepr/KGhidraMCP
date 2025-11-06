
package io.github.nonsleepr.mcp.tools

import io.github.nonsleepr.mcp.*
import ghidra.program.model.listing.*
import ghidra.program.model.symbol.*
import io.modelcontextprotocol.kotlin.sdk.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server

/**
 * Register listing-related MCP tools for browsing program data
 */
fun registerListingTools(server: Server, context: GhidraContext) {
    
    // Tool: list_methods
    server.addTool(
        name = "list_methods",
        description = "List all methods/functions in the program with pagination support. Returns function names.",
        inputSchema = createPaginatedInputSchema()
    ) { request ->
        try {
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                listMethods(context, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to list methods: ${e.message}")
        }
    }
    
    // Tool: list_classes
    server.addTool(
        name = "list_classes",
        description = "List all classes/namespaces in the program with pagination support.",
        inputSchema = createPaginatedInputSchema()
    ) { request: CallToolRequest ->
        try {
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                listClasses(context, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to list classes: ${e.message}")
        }
    }
    
    // Tool: list_segments
    server.addTool(
        name = "list_segments",
        description = "List all memory segments/blocks in the program with their address ranges.",
        inputSchema = createPaginatedInputSchema()
    ) { request: CallToolRequest ->
        try {
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                listSegments(context, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to list segments: ${e.message}")
        }
    }
    
    // Tool: list_imports
    server.addTool(
        name = "list_imports",
        description = "List all imported symbols in the program.",
        inputSchema = createPaginatedInputSchema()
    ) { request: CallToolRequest ->
        try {
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                listImports(context, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to list imports: ${e.message}")
        }
    }
    
    // Tool: list_exports
    server.addTool(
        name = "list_exports",
        description = "List all exported symbols in the program.",
        inputSchema = createPaginatedInputSchema()
    ) { request: CallToolRequest ->
        try {
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                listExports(context, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to list exports: ${e.message}")
        }
    }
    
    // Tool: list_namespaces
    server.addTool(
        name = "list_namespaces",
        description = "List all namespaces in the program.",
        inputSchema = createPaginatedInputSchema()
    ) { request: CallToolRequest ->
        try {
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                listNamespaces(context, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to list namespaces: ${e.message}")
        }
    }
    
    // Tool: list_data_items
    server.addTool(
        name = "list_data_items",
        description = "List all defined data items in the program with their addresses and values.",
        inputSchema = createPaginatedInputSchema()
    ) { request: CallToolRequest ->
        try {
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                listDataItems(context, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to list data items: ${e.message}")
        }
    }
    
    // Tool: list_strings
    server.addTool(
        name = "list_strings",
        description = "List all defined strings in the program with their addresses and values. " +
                     "Optionally filter by a search term.",
        inputSchema = createPaginatedInputSchema(
            additionalProperties = mapOf(
                "filter" to kotlinx.serialization.json.JsonObject(mapOf(
                    "type" to kotlinx.serialization.json.JsonPrimitive("string"),
                    "description" to kotlinx.serialization.json.JsonPrimitive("Optional filter to search for strings containing this text")
                ))
            )
        )
    ) { request: CallToolRequest ->
        try {
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            val filter = request.arguments.getStringParam("filter")
            
            val result = context.runInSwingThreadWithResult {
                listStrings(context, offset, limit, filter)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to list strings: ${e.message}")
        }
    }
}

// Helper functions

private fun listMethods(context: GhidraContext, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val names = mutableListOf<String>()
    for (func in program.functionManager.getFunctions(true)) {
        names.add(func.name)
    }
    
    return paginateList(names, offset, limit)
}

private fun listClasses(context: GhidraContext, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val classNames = mutableSetOf<String>()
    for (symbol in program.symbolTable.getAllSymbols(true)) {
        val ns = symbol.parentNamespace
        if (ns != null && !ns.isGlobal) {
            classNames.add(ns.name)
        }
    }
    
    val sorted = classNames.sorted()
    return paginateList(sorted, offset, limit)
}
private fun listSegments(context: GhidraContext, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val lines = mutableListOf<String>()
    for (block in program.memory.blocks) {
        lines.add("${block.name}: ${block.start} - ${block.end}")
    }
    
    return paginateList(lines, offset, limit)
}

private fun listImports(context: GhidraContext, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val lines = mutableListOf<String>()
    for (symbol in program.symbolTable.externalSymbols) {
        lines.add("${symbol.name} -> ${symbol.address}")
    }
    
    return paginateList(lines, offset, limit)
}

private fun listExports(context: GhidraContext, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    val table = program.symbolTable
    val it = table.getAllSymbols(true)
    
    val lines = mutableListOf<String>()
    while (it.hasNext()) {
        val symbol = it.next()
        if (symbol.isExternalEntryPoint) {
            lines.add("${symbol.name} -> ${symbol.address}")
        }
    }
    
    return paginateList(lines, offset, limit)
}

private fun listNamespaces(context: GhidraContext, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val namespaces = mutableSetOf<String>()
    val globalNamespace = program.globalNamespace
    for (symbol in program.symbolTable.getAllSymbols(true)) {
        val ns = symbol.parentNamespace
        if (ns != null && ns != globalNamespace) {
            namespaces.add(ns.name)
        }
    }
    
    val sorted = namespaces.sorted()
    return paginateList(sorted, offset, limit)
}

private fun listDataItems(context: GhidraContext, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val lines = mutableListOf<String>()
    for (block in program.memory.blocks) {
        val dataIt = program.listing.getDefinedData(block.start, true)
        while (dataIt.hasNext()) {
            val data = dataIt.next()
            if (block.contains(data.address)) {
                val label = data.label ?: "(unnamed)"
                val valRepr = data.defaultValueRepresentation
                lines.add("${data.address}: ${label.escapeNonAscii()} = ${valRepr.escapeNonAscii()}")
            }
        }
    }
    
    return paginateList(lines, offset, limit)
}

private fun listStrings(context: GhidraContext, offset: Int, limit: Int, filter: String?): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val lines = mutableListOf<String>()
    val dataIt = program.listing.getDefinedData(true)
    
    while (dataIt.hasNext()) {
        val data = dataIt.next()
        
        if (data != null && isStringData(data)) {
            val value = data.value?.toString() ?: ""
            
            if (filter == null || value.lowercase().contains(filter.lowercase())) {
                val escapedValue = escapeString(value)
                lines.add("${data.address}: \"$escapedValue\"")
            }
        }
    }
    
    return paginateList(lines, offset, limit)
}
        