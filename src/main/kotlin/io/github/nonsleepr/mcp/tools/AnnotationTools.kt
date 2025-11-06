
package io.github.nonsleepr.mcp.tools

import io.github.nonsleepr.mcp.*
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import io.modelcontextprotocol.kotlin.sdk.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Register annotation-related MCP tools for adding comments and setting types
 */
fun registerAnnotationTools(server: Server, context: GhidraContext) {
    
    // Tool: set_decompiler_comment
    server.addTool(
        name = "set_decompiler_comment",
        description = "Set a comment for an address in the decompiler view (PRE_COMMENT). Returns success or failure message.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(mapOf(
                "address" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Address in hex format (e.g., 0x1400010a0)")
                )),
                "comment" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Comment text to add")
                ))
            )),
            required = listOf("address", "comment")
        )
    ) { request: CallToolRequest ->
        try {
            val address = request.arguments.getRequiredStringParam("address")
            val comment = request.arguments.getRequiredStringParam("comment")
            
            val result = context.runInSwingThreadWithResult {
                setDecompilerComment(context, address, comment)
            }
            
            if (result) {
                createSuccessResult("Successfully set decompiler comment at '$address'")
            } else {
                createErrorResult("Failed to set decompiler comment")
            }
        } catch (e: Exception) {
            createErrorResult("Failed to set decompiler comment: ${e.message}")
        }
    }
    
    // Tool: set_disassembly_comment
    server.addTool(
        name = "set_disassembly_comment",
        description = "Set a comment for an address in the disassembly view (EOL_COMMENT). Returns success or failure message.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(mapOf(
                "address" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Address in hex format (e.g., 0x1400010a0)")
                )),
                "comment" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Comment text to add")
                ))
            )),
            required = listOf("address", "comment")
        )
    ) { request: CallToolRequest ->
        try {
            val address = request.arguments.getRequiredStringParam("address")
            val comment = request.arguments.getRequiredStringParam("comment")
            
            val result = context.runInSwingThreadWithResult {
                setDisassemblyComment(context, address, comment)
            }
            
            if (result) {
                createSuccessResult("Successfully set disassembly comment at '$address'")
            } else {
                createErrorResult("Failed to set disassembly comment")
            }
        } catch (e: Exception) {
            createErrorResult("Failed to set disassembly comment: ${e.message}")
        }
    }
    
    // Tool: set_function_prototype
    server.addTool(
        name = "set_function_prototype",
        description = "Set the function signature/prototype at a given address. " +
                     "Example: 'int foo(char* str, int count)'. Returns success or failure message.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(mapOf(
                "function_address" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Function address in hex format (e.g., 0x1400010a0)")
                )),
                "prototype" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Function prototype/signature (e.g., 'int foo(char* str, int count)')")
                ))
            )),
            required = listOf("function_address", "prototype")
        )
    ) { request: CallToolRequest ->
        try {
            val functionAddress = request.arguments.getRequiredStringParam("function_address")
            val prototype = request.arguments.getRequiredStringParam("prototype")
            
            val result = context.runInSwingThreadWithResult {
                setFunctionPrototype(context, functionAddress, prototype)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to set function prototype: ${e.message}")
        }
    }
    
    // Tool: set_local_variable_type
    server.addTool(
        name = "set_local_variable_type",
        description = "Set the data type of a local variable in a function. " +
                     "Example types: 'int', 'char*', 'DWORD', 'PVOID'. Returns success or failure message.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(mapOf(
                "function_address" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Function address in hex format (e.g., 0x1400010a0)")
                )),
                "variable_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Variable name to modify")
                )),
                "new_type" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("New data type (e.g., 'int', 'char*', 'DWORD')")
                ))
            )),
            required = listOf("function_address", "variable_name", "new_type")
        )
    ) { request: CallToolRequest ->
        try {
            val functionAddress = request.arguments.getRequiredStringParam("function_address")
            val variableName = request.arguments.getRequiredStringParam("variable_name")
            val newType = request.arguments.getRequiredStringParam("new_type")
            
            val result = context.runInSwingThreadWithResult {
                setLocalVariableType(context, functionAddress, variableName, newType)
            }
            
            if (result) {
                createSuccessResult("Successfully set variable '$variableName' type to '$newType'")
            } else {
                createErrorResult("Failed to set variable type")
            }
        } catch (e: Exception) {
            createErrorResult("Failed to set variable type: ${e.message}")
        }
    }
}

// Helper functions

private fun setCommentAtAddress(context: GhidraContext, addressStr: String, comment: String,
                                commentType: CommentType, transactionName: String): Boolean {
    val program = context.getCurrentProgram() ?: return false
    
    var success = false
    val tx = program.startTransaction(transactionName)
    try {
        val addr = program.addressFactory.getAddress(addressStr)
        program.listing.setComment(addr, commentType, comment)
        success = true
    } catch (e: Exception) {
        ghidra.util.Msg.error(null, "Error setting $transactionName", e)
    } finally {
        program.endTransaction(tx, success)
    }
    
    return success
}

private fun setDecompilerComment(context: GhidraContext, addressStr: String, comment: String): Boolean {
    return setCommentAtAddress(context, addressStr, comment, CommentType.PRE, "Set decompiler comment")
}

private fun setDisassemblyComment(context: GhidraContext, addressStr: String, comment: String): Boolean {
    return setCommentAtAddress(context, addressStr, comment, CommentType.EOL, "Set disassembly comment")
}

private fun setFunctionPrototype(context: GhidraContext, functionAddrStr: String, prototype: String): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    if (functionAddrStr.isEmpty() || prototype.isEmpty()) {
        return "Function address and prototype are required"
    }
    
    try {
        val addr = program.addressFactory.getAddress(functionAddrStr)
        val func = program.functionManager.getFunctionAt(addr)
            ?: program.functionManager.getFunctionContaining(addr)
            ?: return "Could not find function at address: $functionAddrStr"
        
        ghidra.util.Msg.info(null, "Setting prototype for function ${func.name}: $prototype")
        
        // Add a comment showing the prototype being set
        val txComment = program.startTransaction("Add prototype comment")
        try {
            program.listing.setComment(
                func.entryPoint,
                CommentType.PLATE,
                "Setting prototype: $prototype"
            )
        } finally {
            program.endTransaction(txComment, true)
        }
        
        // Parse and apply the function signature
        val txProto = program.startTransaction("Set function prototype")
        var success = false
        try {
            val dtm = program.dataTypeManager
            // DataTypeManagerService is optional for parsing - pass null if not available
            val dtms: ghidra.app.services.DataTypeManagerService? = null
            
            val parser = ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms)
            val sig = parser.parse(null, prototype)
            
            if (sig == null) {
                return "Failed to parse function prototype"
            }
            
            val cmd = ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                addr, sig, SourceType.USER_DEFINED
            )
            
            val cmdResult = cmd.applyTo(program, ghidra.util.task.ConsoleTaskMonitor())
            
            if (cmdResult) {
                success = true
                return "Successfully applied function signature"
            } else {
                return "Command failed: ${cmd.statusMsg}"
            }
        } catch (e: Exception) {
            return "Error applying function signature: ${e.message}"
        } finally {
            program.endTransaction(txProto, success)
        }
    } catch (e: Exception) {
        return "Error setting function prototype: ${e.message}"
    }
}

private fun setLocalVariableType(context: GhidraContext, functionAddrStr: String,
                                 variableName: String, newType: String): Boolean {
    val program = context.getCurrentProgram() ?: return false
    
    if (functionAddrStr.isEmpty() || variableName.isEmpty() || newType.isEmpty()) {
        return false
    }
    
    try {
        val addr = program.addressFactory.getAddress(functionAddrStr)
        val func = program.functionManager.getFunctionAt(addr)
            ?: program.functionManager.getFunctionContaining(addr)
            ?: return false
        
        val decomp = ghidra.app.decompiler.DecompInterface()
        decomp.openProgram(program)
        decomp.setSimplificationStyle("decompile")
        
        val results = decomp.decompileFunction(func, 60, ghidra.util.task.ConsoleTaskMonitor())
        
        if (!results.decompileCompleted()) {
            ghidra.util.Msg.error(null, "Could not decompile function: ${results.errorMessage}")
            return false
        }
        
        val highFunction = results.highFunction ?: return false
        
        // Find the symbol by name
        val symbol = findSymbolByName(highFunction, variableName) ?: return false
        
        val highVar = symbol.highVariable ?: return false
        
        ghidra.util.Msg.info(null, "Found high variable for: $variableName with current type ${highVar.dataType.name}")
        
        // Find the data type
        val dtm = program.dataTypeManager
        val dataType = resolveDataType(dtm, newType) ?: return false
        
        ghidra.util.Msg.info(null, "Using data type: ${dataType.name} for variable $variableName")
        
        // Apply the type change in a transaction
        var success = false
        val tx = program.startTransaction("Set variable type")
        try {
            ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
                symbol,
                symbol.name,
                dataType,
                SourceType.USER_DEFINED
            )
            success = true
            ghidra.util.Msg.info(null, "Successfully set variable type using HighFunctionDBUtil")
        } catch (e: Exception) {
            ghidra.util.Msg.error(null, "Error setting variable type: ${e.message}")
        } finally {
            program.endTransaction(tx, success)
        }
        
        return success
    } catch (e: Exception) {
        ghidra.util.Msg.error(null, "Error setting variable type: ${e.message}")
        return false
    }
}

private fun findSymbolByName(highFunction: ghidra.program.model.pcode.HighFunction,
                            variableName: String): ghidra.program.model.pcode.HighSymbol? {
    val symbols = highFunction.localSymbolMap.symbols
    while (symbols.hasNext()) {
        val s = symbols.next()
        if (s.name == variableName) {
            return s
        }
    }
    return null
}

private fun resolveDataType(dtm: ghidra.program.model.data.DataTypeManager,
                           typeName: String): ghidra.program.model.data.DataType? {
    // First try to find exact match in all categories
    var dataType = findDataTypeByNameInAllCategories(dtm, typeName)
    if (dataType != null) {
        ghidra.util.Msg.info(null, "Found exact data type match: ${dataType.pathName}")
        return dataType
    }
    
    // Check for Windows-style pointer types (PXXX)
    if (typeName.startsWith("P") && typeName.length > 1) {
        val baseTypeName = typeName.substring(1)
        
        // Special case for PVOID
        if (baseTypeName == "VOID") {
            return ghidra.program.model.data.PointerDataType(dtm.getDataType("/void"))
        }
        
        // Try to find the base type
        val baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName)
        if (baseType != null) {
            return ghidra.program.model.data.PointerDataType(baseType)
        }
        
        ghidra.util.Msg.warn(null, "Base type not found for $typeName, defaulting to void*")
        return ghidra.program.model.data.PointerDataType(dtm.getDataType("/void"))
    }
    
    // Handle common built-in types
    return when (typeName.lowercase()) {
        "int", "long" -> dtm.getDataType("/int")
        "uint", "unsigned int", "unsigned long", "dword" -> dtm.getDataType("/uint")
        "short" -> dtm.getDataType("/short")
        "ushort", "unsigned short", "word" -> dtm.getDataType("/ushort")
        "char", "byte" -> dtm.getDataType("/char")
        "uchar", "unsigned char" -> dtm.getDataType("/uchar")
        "longlong", "__int64" -> dtm.getDataType("/longlong")
        "ulonglong", "unsigned __int64" -> dtm.getDataType("/ulonglong")
        "bool", "boolean" -> dtm.getDataType("/bool")
        "void" -> dtm.getDataType("/void")
        else -> {
            // Try as a direct path
            val directType = dtm.getDataType("/$typeName")
            if (directType != null) {
                return directType
            }
            
            // Fallback to int if we couldn't find it
            ghidra.util.Msg.warn(null, "Unknown type: $typeName, defaulting to int")
            dtm.getDataType("/int")
        }
    }
}

private fun findDataTypeByNameInAllCategories(dtm: ghidra.program.model.data.DataTypeManager,
                                             typeName: String): ghidra.program.model.data.DataType? {
    // Try exact match first
    var result = searchByNameInAllCategories(dtm, typeName)
    if (result != null) {
        return result
    }
    
    // Try lowercase
    return searchByNameInAllCategories(dtm, typeName.lowercase())
}

private fun searchByNameInAllCategories(dtm: ghidra.program.model.data.DataTypeManager,
                                       name: String): ghidra.program.model.data.DataType? {
    val allTypes = dtm.allDataTypes
    while (allTypes.hasNext()) {
        val dt = allTypes.next()
        // Check if the name matches exactly (case-sensitive)
        if (dt.name == name) {
            return dt
        }
        // For case-insensitive, we want an exact match except for case
        if (dt.name.equals(name, ignoreCase = true)) {
            return dt
        }
    }
    return null
}