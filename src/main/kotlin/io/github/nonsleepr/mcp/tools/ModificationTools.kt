
package io.github.nonsleepr.mcp.tools

import io.github.nonsleepr.mcp.*
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import io.modelcontextprotocol.kotlin.sdk.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Register modification-related MCP tools for renaming elements
 */
fun registerModificationTools(server: Server, context: GhidraContext) {
    
    // Tool: rename_function
    server.addTool(
        name = "rename_function",
        description = "Rename a function by its current name. Returns success or failure message.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(mapOf(
                "old_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Current function name")
                )),
                "new_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("New function name")
                ))
            )),
            required = listOf("old_name", "new_name")
        )
    ) { request: CallToolRequest ->
        try {
            val oldName = request.arguments.getRequiredStringParam("old_name")
            val newName = request.arguments.getRequiredStringParam("new_name")
            
            val result = context.runInSwingThreadWithResult {
                renameFunction(context, oldName, newName)
            }
            
            if (result) {
                createSuccessResult("Successfully renamed function from '$oldName' to '$newName'")
            } else {
                createErrorResult("Failed to rename function")
            }
        } catch (e: Exception) {
            createErrorResult("Failed to rename function: ${e.message}")
        }
    }
    
    // Tool: rename_function_by_address
    server.addTool(
        name = "rename_function_by_address",
        description = "Rename a function by its address. Returns success or failure message.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(mapOf(
                "address" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Function address in hex format (e.g., 0x1400010a0)")
                )),
                "new_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("New function name")
                ))
            )),
            required = listOf("address", "new_name")
        )
    ) { request: CallToolRequest ->
        try {
            val address = request.arguments.getRequiredStringParam("address")
            val newName = request.arguments.getRequiredStringParam("new_name")
            
            val result = context.runInSwingThreadWithResult {
                renameFunctionByAddress(context, address, newName)
            }
            
            if (result) {
                createSuccessResult("Successfully renamed function at '$address' to '$newName'")
            } else {
                createErrorResult("Failed to rename function")
            }
        } catch (e: Exception) {
            createErrorResult("Failed to rename function: ${e.message}")
        }
    }
    
    // Tool: rename_variable
    server.addTool(
        name = "rename_variable",
        description = "Rename a local variable in a function. Requires decompilation. Returns success or failure message.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(mapOf(
                "function_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Name of the function containing the variable")
                )),
                "old_var_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Current variable name")
                )),
                "new_var_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("New variable name")
                ))
            )),
            required = listOf("function_name", "old_var_name", "new_var_name")
        )
    ) { request: CallToolRequest ->
        try {
            val functionName = request.arguments.getRequiredStringParam("function_name")
            val oldVarName = request.arguments.getRequiredStringParam("old_var_name")
            val newVarName = request.arguments.getRequiredStringParam("new_var_name")
            
            val result = context.runInSwingThreadWithResult {
                renameVariable(context, functionName, oldVarName, newVarName)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to rename variable: ${e.message}")
        }
    }
    
    // Tool: rename_data
    server.addTool(
        name = "rename_data",
        description = "Rename a data item at a specific address. Returns success or failure message.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(mapOf(
                "address" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("Data address in hex format (e.g., 0x1400010a0)")
                )),
                "new_name" to JsonObject(mapOf(
                    "type" to JsonPrimitive("string"),
                    "description" to JsonPrimitive("New data label name")
                ))
            )),
            required = listOf("address", "new_name")
        )
    ) { request: CallToolRequest ->
        try {
            val address = request.arguments.getRequiredStringParam("address")
            val newName = request.arguments.getRequiredStringParam("new_name")
            
            context.runInSwingThreadWithResult {
                renameData(context, address, newName)
            }
            createSuccessResult("Successfully renamed data at '$address' to '$newName'")
        } catch (e: Exception) {
            createErrorResult("Failed to rename data: ${e.message}")
        }
    }
}

// Helper functions

private fun renameFunction(context: GhidraContext, oldName: String, newName: String): Boolean {
    val program = context.getCurrentProgram() ?: return false
    
    var success = false
    val tx = program.startTransaction("Rename function via MCP")
    try {
        for (func in program.functionManager.getFunctions(true)) {
            if (func.name == oldName) {
                func.setName(newName, SourceType.USER_DEFINED)
                success = true
                break
            }
        }
    } catch (e: Exception) {
        ghidra.util.Msg.error(null, "Error renaming function", e)
    } finally {
        program.endTransaction(tx, success)
    }
    
    return success
}

private fun renameFunctionByAddress(context: GhidraContext, addressStr: String, newName: String): Boolean {
    val program = context.getCurrentProgram() ?: return false
    
    var success = false
    val tx = program.startTransaction("Rename function by address")
    try {
        val addr = program.addressFactory.getAddress(addressStr)
        val func = program.functionManager.getFunctionAt(addr)
            ?: program.functionManager.getFunctionContaining(addr)
        
        if (func != null) {
            func.setName(newName, SourceType.USER_DEFINED)
            success = true
        }
    } catch (e: Exception) {
        ghidra.util.Msg.error(null, "Error renaming function", e)
    } finally {
        program.endTransaction(tx, success)
    }
    
    return success
}

private fun renameVariable(context: GhidraContext, functionName: String, oldVarName: String, newVarName: String): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val decomp = ghidra.app.decompiler.DecompInterface()
    decomp.openProgram(program)
    
    var func: Function? = null
    for (f in program.functionManager.getFunctions(true)) {
        if (f.name == functionName) {
            func = f
            break
        }
    }
    
    if (func == null) {
        return "Function not found"
    }
    
    val result = decomp.decompileFunction(func, 30, ghidra.util.task.ConsoleTaskMonitor())
    if (result == null || !result.decompileCompleted()) {
        return "Decompilation failed"
    }
    
    val highFunction = result.highFunction ?: return "Decompilation failed (no high function)"
    val localSymbolMap = highFunction.localSymbolMap ?: return "Decompilation failed (no local symbol map)"
    
    var highSymbol: ghidra.program.model.pcode.HighSymbol? = null
    val symbols = localSymbolMap.symbols
    while (symbols.hasNext()) {
        val symbol = symbols.next()
        val symbolName = symbol.name
        
        if (symbolName == oldVarName) {
            highSymbol = symbol
        }
        if (symbolName == newVarName) {
            return "Error: A variable with name '$newVarName' already exists in this function"
        }
    }
    
    if (highSymbol == null) {
        return "Variable not found"
    }
    
    val commitRequired = checkFullCommit(highSymbol, highFunction)
    
    var success = false
    val tx = program.startTransaction("Rename variable")
    try {
        if (commitRequired) {
            ghidra.program.model.pcode.HighFunctionDBUtil.commitParamsToDatabase(
                highFunction, false,
                ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
                func.signatureSource
            )
        }
        ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
            highSymbol,
            newVarName,
            null,
            SourceType.USER_DEFINED
        )
        success = true
    } catch (e: Exception) {
        ghidra.util.Msg.error(null, "Failed to rename variable", e)
    } finally {
        program.endTransaction(tx, true)
    }
    
    return if (success) "Variable renamed" else "Failed to rename variable"
}

/**
 * Check if full commit is required for parameter changes
 * Copied from AbstractDecompilerAction.checkFullCommit
 */
private fun checkFullCommit(highSymbol: ghidra.program.model.pcode.HighSymbol?,
                            hfunction: ghidra.program.model.pcode.HighFunction): Boolean {
    if (highSymbol != null && !highSymbol.isParameter) {
        return false
    }
    val function = hfunction.function
    val parameters = function.parameters
    val localSymbolMap = hfunction.localSymbolMap
    val numParams = localSymbolMap.numParams
    if (numParams != parameters.size) {
        return true
    }
    
    for (i in 0 until numParams) {
        val param = localSymbolMap.getParamSymbol(i)
        if (param.categoryIndex != i) {
            return true
        }
        val storage = param.storage
        if (storage.compareTo(parameters[i].variableStorage) != 0) {
            return true
        }
    }
    
    return false
}

private fun renameData(context: GhidraContext, addressStr: String, newName: String) {
    val program = context.getCurrentProgram() ?: return
    
    val tx = program.startTransaction("Rename data")
    try {
        val addr = program.addressFactory.getAddress(addressStr)
        val listing = program.listing
        val data = listing.getDefinedDataAt(addr)
        if (data != null) {
            val symTable = program.symbolTable
            val symbol = symTable.getPrimarySymbol(addr)
            if (symbol != null) {
                symbol.setName(newName, SourceType.USER_DEFINED)
            } else {
                symTable.createLabel(addr, newName, SourceType.USER_DEFINED)
            }
        }
    } catch (e: Exception) {
        ghidra.util.Msg.error(null, "Rename data error", e)
    } finally {
        program.endTransaction(tx, true)
    }
}