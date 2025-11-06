package io.github.nonsleepr.mcp

import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.TextContent
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Utility functions for MCP tool handling
 */

/**
 * Create a successful tool result with text content
 */
fun createSuccessResult(text: String): CallToolResult {
    return CallToolResult(
        content = listOf(TextContent(text = text))
    )
}

/**
 * Create an error tool result
 */
fun createErrorResult(message: String): CallToolResult {
    return CallToolResult(
        content = listOf(TextContent(text = "Error: $message")),
        isError = true
    )
}

/**
 * Paginate a list of items and format as string
 */
fun <T> paginateList(
    items: List<T>,
    offset: Int,
    limit: Int,
    formatter: (T) -> String = { it.toString() }
): String {
    val paginated = items.drop(offset).take(limit)
    return if (paginated.isEmpty()) {
        "No items found"
    } else {
        paginated.joinToString("\n", transform = formatter)
    }
}

/**
 * Get a string parameter from tool arguments
 */
fun JsonObject.getStringParam(name: String): String? {
    return this[name]?.let { element ->
        when {
            element is JsonPrimitive && element.isString -> element.content
            else -> null
        }
    }
}

/**
 * Get a required string parameter from tool arguments
 */
fun JsonObject.getRequiredStringParam(name: String): String {
    return getStringParam(name) ?: throw IllegalArgumentException("Required parameter '$name' is missing or invalid")
}

/**
 * Get an integer parameter from tool arguments with default value
 */
fun JsonObject.getIntParam(name: String, default: Int): Int {
    return this[name]?.let { element ->
        when {
            element is JsonPrimitive && element.content.toIntOrNull() != null -> element.content.toInt()
            else -> default
        }
    } ?: default
}

/**
 * Get an integer parameter from tool arguments (nullable version)
 */
fun JsonObject.getIntParam(name: String): Int? {
    return this[name]?.let { element ->
        when {
            element is JsonPrimitive && element.content.toIntOrNull() != null -> element.content.toInt()
            else -> null
        }
    }
}

/**
 * Escape non-ASCII characters in a string for safe display
 */
fun String.escapeNonAscii(): String {
    return this.map { char ->
        if (char.code in 32..126) char.toString()
        else "\\u%04x".format(char.code)
    }.joinToString("")
}

/**
 * Create JSON input schema for a tool with pagination parameters
 */
fun createPaginatedInputSchema(
    additionalProperties: Map<String, JsonObject> = emptyMap(),
    additionalRequired: List<String> = emptyList()
): io.modelcontextprotocol.kotlin.sdk.Tool.Input {
    val properties = mutableMapOf(
        "offset" to JsonObject(mapOf(
            "type" to JsonPrimitive("number"),
            "description" to JsonPrimitive("Pagination offset (default: 0)"),
            "default" to JsonPrimitive(0)
        )),
        "limit" to JsonObject(mapOf(
            "type" to JsonPrimitive("number"),
            "description" to JsonPrimitive("Maximum number of items to return (default: 100)"),
            "default" to JsonPrimitive(100)
        ))
    )
    properties.putAll(additionalProperties)
    
    return io.modelcontextprotocol.kotlin.sdk.Tool.Input(
        properties = JsonObject(properties),
        required = additionalRequired
    )
}

/**
 * Create JSON input schema for a simple string parameter tool
 */
fun createStringInputSchema(
    paramName: String,
    description: String,
    required: Boolean = true
): io.modelcontextprotocol.kotlin.sdk.Tool.Input {
    return io.modelcontextprotocol.kotlin.sdk.Tool.Input(
        properties = JsonObject(mapOf(
            paramName to JsonObject(mapOf(
                "type" to JsonPrimitive("string"),
                "description" to JsonPrimitive(description)
            ))
        )),
        required = if (required) listOf(paramName) else emptyList()
    )
}

/**
 * Check if data is a string type
 */
fun isStringData(data: ghidra.program.model.listing.Data?): Boolean {
    if (data == null) return false
    val typeName = data.dataType.name.lowercase()
    return typeName.contains("string") || typeName.contains("char") || typeName == "unicode"
}

/**
 * Escape special characters in a string for display
 */
fun escapeString(input: String?): String {
    if (input == null) return ""
    
    return buildString {
        for (c in input) {
            when {
                c.code in 32..126 -> append(c)
                c == '\n' -> append("\\n")
                c == '\r' -> append("\\r")
                c == '\t' -> append("\\t")
                else -> append("\\x%02x".format(c.code and 0xFF))
            }
        }
    }
}