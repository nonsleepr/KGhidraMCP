
package io.github.nonsleepr.mcp.tools

import io.github.nonsleepr.mcp.*
import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.*
import ghidra.util.task.ConsoleTaskMonitor
import io.modelcontextprotocol.kotlin.sdk.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Register decompilation-related MCP tools
 */
fun registerDecompilationTools(server: Server, context: GhidraContext) {
    
    // Tool: get_function_by_address
    server.addTool(
        name = "get_function_by_address",
        description = "Get function information by address. Returns function name, entry point, and signature.",
        inputSchema = createStringInputSchema("address", "Memory address in hex format (e.g., 0x1400010a0)")
    ) { request: CallToolRequest ->
        try {
            val address = request.arguments.getRequiredStringParam("address")
            val result = context.runInSwingThreadWithResult {
                getFunctionByAddress(context, address)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to get function: ${e.message}")
        }
    }
    
    // Tool: get_current_function
    server.addTool(
        name = "get_current_function",
        description = "Get the function at the current cursor location in Ghidra. " +
                     "Returns function name, address, and signature.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(emptyMap())
        )
    ) { request: CallToolRequest ->
        try {
            val result = context.runInSwingThreadWithResult {
                getCurrentFunction(context)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to get current function: ${e.message}")
        }
    }
    
    // Tool: decompile_function (legacy by name)
    server.addTool(
        name = "decompile_function",
        description = "Decompile a function by name and return the decompiled C code. " +
                     "Note: Use decompile_function_by_address for more reliable results.",
        inputSchema = createStringInputSchema("name", "Function name to decompile")
    ) { request: CallToolRequest ->
        try {
            val name = request.arguments.getRequiredStringParam("name")
            val result = context.runInSwingThreadWithResult {
                decompileFunctionByName(context, name)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to decompile function: ${e.message}")
        }
    }
    
    // Tool: decompile_function_by_address
    server.addTool(
        name = "decompile_function_by_address",
        description = "Decompile a function at the given address and return the decompiled C code.",
        inputSchema = createStringInputSchema("address", "Memory address in hex format (e.g., 0x1400010a0)")
    ) { request: CallToolRequest ->
        try {
            val address = request.arguments.getRequiredStringParam("address")
            val result = context.runInSwingThreadWithResult {
                decompileFunctionByAddress(context, address)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to decompile function: ${e.message}")
        }
    }
    
    // Tool: disassemble_function
    server.addTool(
        name = "disassemble_function",
        description = "Get assembly code (disassembly) for a function at the given address. " +
                     "Returns address: instruction; comment format for each instruction.",
        inputSchema = createStringInputSchema("address", "Memory address in hex format (e.g., 0x1400010a0)")
    ) { request: CallToolRequest ->
        try {
            val address = request.arguments.getRequiredStringParam("address")
            val result = context.runInSwingThreadWithResult {
                disassembleFunction(context, address)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to disassemble function: ${e.message}")
        }
    }
    
    // Tool: list_functions
    server.addTool(
        name = "list_functions",
        description = "List all functions in the program with their addresses.",
        inputSchema = io.modelcontextprotocol.kotlin.sdk.Tool.Input(
            properties = JsonObject(emptyMap())
        )
    ) { request: CallToolRequest ->
        try {
            val result = context.runInSwingThreadWithResult {
                listFunctions(context)
            }
            createSuccessResult(result)
        } catch (e: Exception) {
            createErrorResult("Failed to list functions: ${e.message}")
        }
    }
}

// Helper functions

private fun getFunctionByAddress(context: GhidraContext, addressStr: String): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val addr = program.addressFactory.getAddress(addressStr)
    val func = getFunctionForAddress(program, addr)
        ?: return "No function found at or containing address $addressStr"
    
    return "Function: ${func.name} at ${func.entryPoint}\nSignature: ${func.signature}"
}

private fun getCurrentFunction(context: GhidraContext): String {
    val location = context.getCurrentLocation() ?: return "No current location"
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val func = program.functionManager.getFunctionContaining(location.address)
        ?: return "No function at current location: ${location.address}"
    
    return "Function: ${func.name} at ${func.entryPoint}\nSignature: ${func.signature}"
}

private fun decompileFunctionByName(context: GhidraContext, name: String): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val decomp = DecompInterface()
    decomp.openProgram(program)
    
    for (func in program.functionManager.getFunctions(true)) {
        if (func.name == name) {
            val result = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
            return if (result != null && result.decompileCompleted()) {
                result.decompiledFunction.c
            } else {
                "Decompilation failed"
            }
        }
    }
    
    return "Function not found"
}

private fun decompileFunctionByAddress(context: GhidraContext, addressStr: String): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val addr = program.addressFactory.getAddress(addressStr)
    val func = getFunctionForAddress(program, addr)
        ?: return "No function found at or containing address $addressStr"
    
    val decomp = DecompInterface()
    decomp.openProgram(program)
    val result = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
    
    return if (result != null && result.decompileCompleted()) {
        result.decompiledFunction.c
    } else {
        "Decompilation failed"
    }
}

private fun disassembleFunction(context: GhidraContext, addressStr: String): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val addr = program.addressFactory.getAddress(addressStr)
    val func = getFunctionForAddress(program, addr)
        ?: return "No function found at or containing address $addressStr"
    
    val result = StringBuilder()
    val listing = program.listing
    val start = func.entryPoint
    val end = func.body.maxAddress
    
    val instructions = listing.getInstructions(func.body as AddressSetView, true)
    while (instructions.hasNext()) {
        val instr = instructions.next()
        if (instr.address > end) break
        
        val comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.address)
        val commentStr = if (comment != null) "; $comment" else ""
        
        result.append("${instr.address}: $instr $commentStr\n")
    }
    
    return result.toString()
}

private fun listFunctions(context: GhidraContext): String {
    val program = context.getCurrentProgram() ?: return "No program loaded"
    
    val result = StringBuilder()
    for (func in program.functionManager.getFunctions(true)) {
        result.append("${func.name} at ${func.entryPoint}\n")
    }
    
    return result.toString()
}

/**
 * Get a function at the given address or containing the address
 */
private fun getFunctionForAddress(program: ghidra.program.model.listing.Program, addr: Address): ghidra.program.model.listing.Function? {
    return program.functionManager.getFunctionAt(addr)
        ?: program.functionManager.getFunctionContaining(addr)
}