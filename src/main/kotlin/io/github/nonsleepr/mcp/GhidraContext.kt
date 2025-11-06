package io.github.nonsleepr.mcp

import ghidra.app.services.CodeViewerService
import ghidra.app.services.ProgramManager
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation
import ghidra.util.Msg
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import javax.swing.SwingUtilities
import java.util.concurrent.atomic.AtomicReference

/**
 * Thread-safe wrapper for Ghidra API access.
 * All Ghidra API calls must be executed on the Swing EDT.
 */
class GhidraContext(private val tool: PluginTool) {
    
    /**
     * Get the currently open program
     */
    fun getCurrentProgram(): Program? {
        return tool.getService(ProgramManager::class.java)?.currentProgram
    }
    
    /**
     * Get the current cursor location in the code viewer
     */
    fun getCurrentLocation(): ProgramLocation? {
        val codeViewerService = tool.getService(CodeViewerService::class.java)
        return codeViewerService?.currentLocation
    }
    
    /**
     * Execute an action on the Swing EDT and wait for completion
     */
    fun <T> runInSwingThreadWithResult(action: () -> T): T {
        if (SwingUtilities.isEventDispatchThread()) {
            return action()
        }
        
        val result = AtomicReference<T>()
        val exception = AtomicReference<Throwable>()
        
        SwingUtilities.invokeAndWait {
            try {
                result.set(action())
            } catch (e: Throwable) {
                exception.set(e)
            }
        }
        
        exception.get()?.let { throw it }
        return result.get()
    }
    
    /**
     * Execute an action on the Swing EDT using coroutines
     */
    suspend fun <T> runOnSwing(action: () -> T): T {
        return withContext(Dispatchers.Swing) {
            action()
        }
    }
    
    /**
     * Log an info message to Ghidra console
     */
    fun logInfo(message: String) {
        Msg.info(this, message)
    }
    
    /**
     * Log an error message to Ghidra console
     */
    fun logError(message: String, error: Throwable? = null) {
        if (error != null) {
            Msg.error(this, message, error)
        } else {
            Msg.error(this, message)
        }
    }
}