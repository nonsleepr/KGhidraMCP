package io.github.nonsleepr.mcp

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.sse.*
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import io.github.nonsleepr.mcp.tools.*

/**
 * Manages the MCP server lifecycle and tool registration
 */
class McpServerManager(
    private val context: GhidraContext,
    private var port: Int = 3001,
    private var host: String = "127.0.0.1"
) {
    private var server: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration>? = null
    
    /**
     * Reconfigure the server with new port and host
     * Will restart the server if it's currently running
     */
    fun reconfigure(newPort: Int, newHost: String) {
        val wasRunning = isRunning()
        if (wasRunning) {
            stop()
        }
        
        port = newPort
        host = newHost
        
        if (wasRunning) {
            start()
        }
    }
    
    /**
     * Start the MCP server
     */
    fun start() {
        if (server != null) {
            context.logInfo("MCP server is already running")
            return
        }
        
        context.logInfo("Starting MCP server on $host:$port...")
        
        try {
            server = embeddedServer(Netty, port = port, host = host) {
                mcpModule(context)
            }
            
            server?.start(wait = false)
            context.logInfo("MCP server started successfully on $host:$port")
            val displayHost = if (host == "0.0.0.0") "localhost" else host
            context.logInfo("MCP SSE endpoint available at: http://$displayHost:$port/mcp")
        } catch (e: Exception) {
            context.logError("Failed to start MCP server on port $port", e)
            server = null
            throw e
        }
    }
    
    /**
     * Stop the MCP server
     */
    fun stop() {
        server?.let {
            context.logInfo("Stopping MCP server...")
            it.stop(1000, 2000)
            server = null
            context.logInfo("MCP server stopped")
        }
    }
    
    /**
     * Check if server is running
     */
    fun isRunning(): Boolean = server != null
}

/**
 * Configure the MCP module for Ktor
 */
fun Application.mcpModule(context: GhidraContext) {
    mcp {
        val mcpServer = Server(
            serverInfo = Implementation(
                name = "ghidra-mcp-server",
                version = System.getProperty("kghidramcp.version", "1.0.0")
            ),
            options = ServerOptions(
                capabilities = ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = null)
                )
            )
        )
        
        // Register all tools
        registerDecompilationTools(mcpServer, context)
        registerListingTools(mcpServer, context)
        registerSearchTools(mcpServer, context)
        registerModificationTools(mcpServer, context)
        registerAnnotationTools(mcpServer, context)
        registerNavigationTools(mcpServer, context)
        
        context.logInfo("All MCP tools registered successfully")
        
        mcpServer
    }
}