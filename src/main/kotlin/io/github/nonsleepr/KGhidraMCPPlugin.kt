package io.github.nonsleepr

import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.DeveloperPluginPackage
import ghidra.framework.plugintool.Plugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.framework.options.Options
import ghidra.util.Msg
import io.github.nonsleepr.mcp.GhidraContext
import io.github.nonsleepr.mcp.McpServerManager

/**
 * Ghidra plugin that provides an MCP (Model Context Protocol) server
 * for interacting with Ghidra's analysis capabilities via AI tools.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "MCP Server Plugin",
    description = "Provides a Model Context Protocol server for AI-powered interaction with Ghidra. " +
                  "Exposes decompilation, analysis, and modification capabilities via MCP tools."
)
class KGhidraMCPPlugin(tool: PluginTool) : Plugin(tool) {
    
    private val context: GhidraContext
    private val serverManager: McpServerManager
    
    companion object {
        private const val OPTION_CATEGORY_NAME = "KGhidraMCP Server"
        private const val PORT_OPTION_NAME = "Server Port"
        private const val DEFAULT_PORT = 3001
        private const val AUTO_START_OPTION_NAME = "Auto-start Server"
        private const val DEFAULT_AUTO_START = true
    }
    
    init {
        Msg.info(this, "KGhidraMCPPlugin loading...")
        
        // Initialize context
        context = GhidraContext(tool)
        
        // Register configuration options
        val options: Options = tool.getOptions(OPTION_CATEGORY_NAME)
        options.registerOption(
            PORT_OPTION_NAME,
            DEFAULT_PORT,
            null,
            "The network port number the MCP server will listen on. " +
            "Requires plugin reload to take effect after changing."
        )
        options.registerOption(
            AUTO_START_OPTION_NAME,
            DEFAULT_AUTO_START,
            null,
            "Automatically start the MCP server when the plugin loads."
        )
        
        // Read port configuration
        val port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT)
        val autoStart = options.getBoolean(AUTO_START_OPTION_NAME, DEFAULT_AUTO_START)
        
        // Initialize server manager
        serverManager = McpServerManager(context, port)
        
        // Auto-start if configured
        if (autoStart) {
            try {
                serverManager.start()
            } catch (e: Exception) {
                Msg.error(this, "Failed to auto-start MCP server", e)
            }
        }
        
        Msg.info(this, "KGhidraMCPPlugin loaded successfully!")
    }
    
    override fun dispose() {
        Msg.info(this, "KGhidraMCPPlugin disposing...")
        try {
            serverManager.stop()
        } catch (e: Exception) {
            Msg.error(this, "Error stopping MCP server during disposal", e)
        }
        super.dispose()
        Msg.info(this, "KGhidraMCPPlugin disposed")
    }
    
    /**
     * Get the MCP server manager (for testing or manual control)
     */
    fun getServerManager(): McpServerManager = serverManager
    
    /**
     * Get the Ghidra context (for testing or extension)
     */
    fun getContext(): GhidraContext = context
}