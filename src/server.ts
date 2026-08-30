import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { allTools } from "./tools/index.js";
import { auditLogger } from "./utils/audit-log.js";

/**
 * GuardMCP Server — Diagram 1 middle layer
 *
 * Layers:
 *  AI Clients (Claude Code, VS Code, Cursor) --MCP stdio--> GuardMCP Server --HTTPS--> NVD/OSV/npm/GitHub
 *
 * Request lifecycle (Diagram 2):
 *  validate -> cache check -> tool dispatcher -> external API -> format result -> audit log
 *  (cache hit returns instantly, bypassing external API)
 */
export function createServer(): Server {
  const server = new Server(
    { name: "GuardMCP", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  // List tools
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: allTools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  }));

  // Call tool — implements request lifecycle
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const tool = allTools.find((t) => t.name === name);
    if (!tool) {
      throw new Error(`Unknown tool: ${name}`);
    }

    const start = Date.now();
    let cacheHit = false;
    try {
      // Tool handler internally does: validate -> cache check -> external API -> format
      const result = await tool.handler(args as Record<string, unknown>);
      cacheHit = Boolean((result as { _meta?: { cacheHit?: boolean } })._meta?.cacheHit);

      const durationMs = Date.now() - start;
      await auditLogger.log(
        auditLogger.createEntry(name, (args as Record<string, unknown>) || {}, durationMs, {
          cacheHit,
          success: true,
        })
      );

      // Strip _meta before returning (MCP protocol doesn't expect it)
      const { _meta, ...clean } = result as { _meta?: unknown } & typeof result;
      return clean;
    } catch (err) {
      const durationMs = Date.now() - start;
      const message = err instanceof Error ? err.message : String(err);
      await auditLogger.log(
        auditLogger.createEntry(name, (args as Record<string, unknown>) || {}, durationMs, {
          cacheHit,
          success: false,
          error: message,
        })
      );
      return {
        content: [{ type: "text" as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

export async function startServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Log to stderr only — stdout is MCP protocol
  console.error("[GuardMCP] Server running on stdio");
}
