#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { MegaSession } from "./mega.js";
import { registerTools } from "./tools.js";

async function main(): Promise<void> {
  const server = new McpServer(
    { name: "mega-mcp", version: "1.0.0" },
    {
      instructions:
        "Tools to manage a MEGA (mega.io) cloud drive: browse, search, upload, download, read/write files, " +
        "move/copy/rename/delete, public links, incoming shares, imports and account quota. " +
        'Remote paths start at the Cloud Drive root "/"; use "trash:/", "inbox:/", "shares:/<name>/" or "id:<handle>" for other locations.',
    }
  );
  const session = new MegaSession();
  registerTools(server, session);

  const shutdown = async () => {
    await session.logout();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await server.connect(new StdioServerTransport());
  console.error("mega-mcp server running on stdio");
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
