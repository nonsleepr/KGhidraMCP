
package io.github.nonsleepr.mcp.tools

import io.github.nonsleepr.mcp.*
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.RefType
import io.modelcontextprotocol.kotlin.sdk.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Register navigation-related MCP tools for cross-references and location queries
 */
fun registerNavigationTools(server: Server, context: GhidraContext) {
    
    // Tool: get_current_address
    server.addTool(
        name = "get_current_address",
        description = "Get the current cursor address in Ghidra's code viewer. Returns the address as a string.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(emptyMap())
        )
    ) { request: CallToolRequest ->
        try {
            val result = context.runInSwingThreadWithResult {
                getCurrentAddress(context)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to get current address: ${e.message}")
        }
    }
    
    // Tool: get_current_function (duplicate from DecompilationTools, but defined in Java original)
    server.addTool(
        name = "get_current_function_info",
        description = "Get information about the function at the current cursor location. Returns function name, address, and signature.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(emptyMap())
        )
    ) { request: CallToolRequest ->
        try {
            val result = context.runInSwingThreadWithResult {
                getCurrentFunctionInfo(context)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to get current function: ${e.message}")
        }
    }
    
    // Tool: get_xrefs_to
    server.addTool(
        name = "get_xrefs_to",
        description = "Get all cross-references TO a specific address. Shows what references the target address.",
        inputSchema = createPaginatedInputSchema(
            additionalProperties = mapOf(
                "address" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Target address in hex format (e.g., 0x1400010a0)")
                ))
            ),
            additionalRequired = listOf("address")
        )
    ) { request: CallToolRequest ->
        try {
            val address = request.arguments.getRequiredStringParam("address")
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                getXrefsTo(context, address, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to get xrefs to address: ${e.message}")
        }
    }
    
    // Tool: get_xrefs_from
    server.addTool(
        name = "get_xrefs_from",
        description = "Get all cross-references FROM a specific address. Shows what the address references.",
        inputSchema = createPaginatedInputSchema(
            additionalProperties = mapOf(
                "address" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Source address in hex format (e.g., 0x1400010a0)")
                ))
            ),
            additionalRequired = listOf("address")
        )
    ) { request: CallToolRequest ->
        try {
            val address = request.arguments.getRequiredStringParam("address")
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                getXrefsFrom(context, address, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to get xrefs from address: ${e.message}")
        }
    }
    
    // Tool: get_function_xrefs
    server.addTool(
        name = "get_function_xrefs",
        description = "Get all cross-references to a function by name. Shows all places that call or reference the function.",
        inputSchema = createPaginatedInputSchema(
            additionalProperties = mapOf(
                "function_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Function name to get references for")
                ))
            ),
            additionalRequired = listOf("function_name")
        )
    ) { request: CallToolRequest ->
        try {
            val functionName = request.arguments.getRequiredStringParam("function_name")
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                getFunctionXrefs(context, functionName, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to get function xrefs: ${e.message}")
        }
    }
    
    // Tool: get_caller_functions
    server.addTool(
        name = "get_caller_functions",
        description = "Get all functions that call a target function by name. Returns list of caller function names.",
        inputSchema = createPaginatedInputSchema(
            additionalProperties = mapOf(
                "function_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Target function name")
                ))
            ),
            additionalRequired = listOf("function_name")
        )
    ) { request: CallToolRequest ->
        try {
            val functionName = request.arguments.getRequiredStringParam("function_name")
            val offset = request.arguments.getIntParam("offset") ?: 0
            val limit = request.arguments.getIntParam("limit") ?: 100
            
            val result = context.runInSwingThreadWithResult {
                getCallerFunctions(context, functionName, offset, limit)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to get caller functions: ${e.message}")
        }
    }
}

// Helper functions

private fun getCurrentAddress(context: GhidraContext): String {
    val location = context.getCurrentLocation()
    return location?.address?.toString() ?: "No current location"
}

private fun getCurrentFunctionInfo(context: GhidraContext): String {
    val location = context.getCurrentLocation() ?: return "No current location"
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val func = program.functionManager.getFunctionContaining(location.address)
        ?: return "No function at current location: ${location.address}"
    
    return "Function: ${func.name} at ${func.entryPoint}\nSignature: ${func.signature}"
}

private fun getXrefsTo(context: GhidraContext, addressStr: String, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    if (addressStr.isEmpty()) {
        return "Address is required"
    }
    
    try {
        val addr = program.addressFactory.getAddress(addressStr)
        val refManager = program.referenceManager
        
        val refIter = refManager.getReferencesTo(addr)
        
        val refs = mutableListOf<String>()
        while (refIter.hasNext()) {
            val ref = refIter.next()
            val fromAddr = ref.fromAddress
            val refType = ref.referenceType
            
            val fromFunc = program.functionManager.getFunctionContaining(fromAddr)
            val funcInfo = if (fromFunc != null) " in ${fromFunc.name}" else ""
            
            refs.add("From $fromAddr$funcInfo [${refType.name}]")
        }
        
        return paginateList(refs, offset, limit)
    } catch (e: Exception) {
        return "Error getting references to address: ${e.message}"
    }
}

private fun getXrefsFrom(context: GhidraContext, addressStr: String, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    if (addressStr.isEmpty()) {
        return "Address is required"
    }
    
    try {
        val addr = program.addressFactory.getAddress(addressStr)
        val refManager = program.referenceManager
        
        val references = refManager.getReferencesFrom(addr)
        
        val refs = mutableListOf<String>()
        for (ref in references) {
            val toAddr = ref.toAddress
            val refType = ref.referenceType
            
            var targetInfo = ""
            val toFunc = program.functionManager.getFunctionAt(toAddr)
            if (toFunc != null) {
                targetInfo = " to function ${toFunc.name}"
            } else {
                val data = program.listing.getDataAt(toAddr)
                if (data != null) {
                    targetInfo = " to data ${data.label ?: data.pathName}"
                }
            }
            
            refs.add("To $toAddr$targetInfo [${refType.name}]")
        }
        
        return paginateList(refs, offset, limit)
    } catch (e: Exception) {
        return "Error getting references from address: ${e.message}"
    }
}

private fun getFunctionXrefs(context: GhidraContext, functionName: String, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    if (functionName.isEmpty()) {
        return "Function name is required"
    }
    
    try {
        val refs = mutableListOf<String>()
        val funcManager = program.functionManager
        for (function in funcManager.getFunctions(true)) {
            if (function.name == functionName) {
                val entryPoint = function.entryPoint
                val refIter = program.referenceManager.getReferencesTo(entryPoint)
                
                while (refIter.hasNext()) {
                    val ref = refIter.next()
                    val fromAddr = ref.fromAddress
                    val refType = ref.referenceType
                    
                    val fromFunc = funcManager.getFunctionContaining(fromAddr)
                    val funcInfo = if (fromFunc != null) " in ${fromFunc.name}" else ""
                    
                    refs.add("From $fromAddr$funcInfo [${refType.name}]")
                }
            }
        }
        
        if (refs.isEmpty()) {
            return "No references found to function: $functionName"
        }
        
        return paginateList(refs, offset, limit)
    } catch (e: Exception) {
        return "Error getting function references: ${e.message}"
    }
}

private fun getCallerFunctions(context: GhidraContext, functionName: String, offset: Int, limit: Int): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    if (functionName.isEmpty()) {
        return "Function name is required"
    }
    
    try {
        val callers = mutableSetOf<String>()
        val funcManager = program.functionManager
        
        for (function in funcManager.getFunctions(true)) {
            if (function.name == functionName) {
                val entryPoint = function.entryPoint
                val refIter = program.referenceManager.getReferencesTo(entryPoint)
                
                while (refIter.hasNext()) {
                    val ref = refIter.next()
                    val fromAddr = ref.fromAddress
                    
                    val fromFunc = funcManager.getFunctionContaining(fromAddr)
                    if (fromFunc != null) {
                        callers.add(fromFunc.name)
                    }
                }
            }
        }
        
        if (callers.isEmpty()) {
            return "No caller functions found for: $functionName"
        }
        
        val sorted = callers.sorted()
        return paginateList(sorted, offset, limit)
    } catch (e: Exception) {
        return "Error getting caller functions: ${e.message}"
    }
}