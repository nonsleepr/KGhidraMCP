
package io.github.nonsleepr

import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.DeveloperPluginPackage
import ghidra.framework.plugintool.Plugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.framework.options.Options
import ghidra.framework.options.OptionsChangeListener
import ghidra.framework.options.ToolOptions
import ghidra.util.Msg
import docking.ActionContext
import docking.action.DockingAction
import docking.action.ToolBarData
import resources.Icons
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
class KGhidraMCPPlugin(tool: PluginTool) : Plugin(tool), OptionsChangeListener {
    
    private val context: GhidraContext
    private val serverManager: McpServerManager
    private lateinit var startAction: DockingAction
    private lateinit var stopAction: DockingAction
    private lateinit var restartAction: DockingAction
    
    companion object {
        private const val OPTION_CATEGORY_NAME = "KGhidraMCP Server"
        private const val PORT_OPTION_NAME = "Server Port"
        private const val DEFAULT_PORT = 3001
        private const val INTERFACE_OPTION_NAME = "Server Interface"
        private const val DEFAULT_INTERFACE = "127.0.0.1"
        private const val AUTO_START_OPTION_NAME = "Auto-start Server"
        private const val DEFAULT_AUTO_START = true
    }
    
    init {
        Msg.info(this, "KGhidraMCPPlugin loading...")
        
        // Initialize context
        context = GhidraContext(tool)
        
        // Register configuration options
        val options: ToolOptions = tool.getOptions(OPTION_CATEGORY_NAME)
        options.registerOption(
            PORT_OPTION_NAME,
            DEFAULT_PORT,
            null,
            "The network port number the MCP server will listen on. " +
            "Changes take effect immediately by restarting the server."
        )
        options.registerOption(
            INTERFACE_OPTION_NAME,
            DEFAULT_INTERFACE,
            null,
            "The network interface the MCP server will bind to. " +
            "Use '127.0.0.1' for localhost only (recommended), or '0.0.0.0' for all interfaces. " +
            "Changes take effect immediately by restarting the server."
        )
        options.registerOption(
            AUTO_START_OPTION_NAME,
            DEFAULT_AUTO_START,
            null,
            "Automatically start the MCP server when the plugin loads."
        )
        
        // Read configuration
        val port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT)
        val host = options.getString(INTERFACE_OPTION_NAME, DEFAULT_INTERFACE)
        val autoStart = options.getBoolean(AUTO_START_OPTION_NAME, DEFAULT_AUTO_START)
        
        // Initialize server manager
        serverManager = McpServerManager(context, port, host)
        
        // Register as options change listener
        options.addOptionsChangeListener(this)
        
        // Create toolbar actions
        createActions()
        
        // Auto-start if configured
        if (autoStart) {
            try {
                serverManager.start()
                updateActionStates()
            } catch (e: Exception) {
                Msg.error(this, "Failed to auto-start MCP server", e)
            }
        }
        
        Msg.info(this, "KGhidraMCPPlugin loaded successfully!")
    }
    
    override fun optionsChanged(options: ToolOptions, optionName: String, oldValue: Any?, newValue: Any?) {
        when (optionName) {
            PORT_OPTION_NAME, INTERFACE_OPTION_NAME -> {
                val port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT)
                val host = options.getString(INTERFACE_OPTION_NAME, DEFAULT_INTERFACE)
                
                Msg.info(this, "Network settings changed to $host:$port, reconfiguring server...")
                try {
                    serverManager.reconfigure(port, host)
                    Msg.info(this, "MCP server reconfigured successfully")
                    updateActionStates()
                } catch (e: Exception) {
                    Msg.error(this, "Failed to reconfigure MCP server", e)
                }
            }
            AUTO_START_OPTION_NAME -> {
                val autoStart = newValue as? Boolean ?: DEFAULT_AUTO_START
                if (autoStart && !serverManager.isRunning()) {
                    try {
                        serverManager.start()
                        Msg.info(this, "MCP server started due to auto-start option")
                        updateActionStates()
                    } catch (e: Exception) {
                        Msg.error(this, "Failed to start MCP server", e)
                    }
                } else if (!autoStart && serverManager.isRunning()) {
                    try {
                        serverManager.stop()
                        Msg.info(this, "MCP server stopped due to auto-start option")
                        updateActionStates()
                    } catch (e: Exception) {
                        Msg.error(this, "Failed to stop MCP server", e)
                    }
                }
            }
        }
    }
    
    private fun createActions() {
        // Start Server Action
        startAction = object : DockingAction("Start MCP Server", name) {
            override fun actionPerformed(context: ActionContext) {
                try {
                    serverManager.start()
                    Msg.info(this@KGhidraMCPPlugin, "MCP server started")
                    updateActionStates()
                } catch (e: Exception) {
                    Msg.error(this@KGhidraMCPPlugin, "Failed to start MCP server", e)
                }
            }
        }.apply {
            description = "Start the MCP server"
            toolBarData = ToolBarData(Icons.ADD_ICON, "MCP")
            isEnabled = !serverManager.isRunning()
        }
        
        // Stop Server Action
        stopAction = object : DockingAction("Stop MCP Server", name) {
            override fun actionPerformed(context: ActionContext) {
                try {
                    serverManager.stop()
                    Msg.info(this@KGhidraMCPPlugin, "MCP server stopped")
                    updateActionStates()
                } catch (e: Exception) {
                    Msg.error(this@KGhidraMCPPlugin, "Failed to stop MCP server", e)
                }
            }
        }.apply {
            description = "Stop the MCP server"
            toolBarData = ToolBarData(Icons.DELETE_ICON, "MCP")
            isEnabled = serverManager.isRunning()
        }
        
        // Restart Server Action
        restartAction = object : DockingAction("Restart MCP Server", name) {
            override fun actionPerformed(context: ActionContext) {
                try {
                    serverManager.stop()
                    serverManager.start()
                    Msg
.info(this@KGhidraMCPPlugin, "MCP server restarted")
                    updateActionStates()
                } catch (e: Exception) {
                    Msg.error(this@KGhidraMCPPlugin, "Failed to restart MCP server", e)
                }
            }
        }.apply {
            description = "Restart the MCP server"
            toolBarData = ToolBarData(Icons.REFRESH_ICON, "MCP")
            isEnabled = serverManager.isRunning()
        }
        
        // Add actions to tool
        tool.addAction(startAction)
        tool.addAction(stopAction)
        tool.addAction(restartAction)
    }
    
    private fun updateActionStates() {
        val isRunning = serverManager.isRunning()
        startAction.isEnabled = !isRunning
        stopAction.isEnabled = isRunning
        restartAction.isEnabled = isRunning
    }
    
    override fun dispose() {
        Msg.info(this, "KGhidraMCPPlugin disposing...")
        
        // Remove options listener
        val options: ToolOptions = tool.getOptions(OPTION_CATEGORY_NAME)
        options.removeOptionsChangeListener(this)
        
        // Remove actions
        tool.removeAction(startAction)
        tool.removeAction(stopAction)
        tool.removeAction(restartAction)
        
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