import fs from "node:fs";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { z } from "zod";
import { File, type Storage } from "megajs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  MegaSession,
  type Node,
  describe,
  ensureLocalDir,
  formatBytes,
  incomingShares,
  nodePath,
  resolveLocal,
  resolveNode,
  splitParent,
} from "./mega.js";

const PATH_HELP =
  'Remote path. "/" is the Cloud Drive root ("/Docs/a.txt"); use "trash:/..." for the Rubbish Bin, ' +
  '"inbox:/..." for the Inbox, "shares:/<ShareName>/..." for incoming shares, or "id:<nodeHandle>" to address a node by id.';

const remotePath = z.string().describe(PATH_HELP);

function ok(data: unknown): CallToolResult {
  return { content: [{ type: "text", text: typeof data === "string" ? data : JSON.stringify(data, null, 2) }] };
}

function fail(err: unknown): CallToolResult {
  const message = err instanceof Error ? err.message : String(err);
  return { isError: true, content: [{ type: "text", text: `Error: ${message}` }] };
}

/** Wraps a handler so thrown errors become MCP tool errors instead of protocol failures. */
function safe<A>(fn: (args: A) => Promise<CallToolResult>) {
  return async (args: A): Promise<CallToolResult> => {
    try {
      return await fn(args);
    } catch (err) {
      return fail(err);
    }
  };
}

function requireFolder(node: Node, ref: string): Node {
  if (!node.directory) throw new Error(`"${ref}" is a file, not a folder`);
  return node;
}

function listTree(node: Node | File, depth: number, maxDepth: number, out: Record<string, unknown>[], limit: number): void {
  for (const child of (node.children ?? []) as (Node | File)[]) {
    if (out.length >= limit) return;
    out.push({ ...describe(child), depth });
    if (child.directory && depth < maxDepth) listTree(child, depth + 1, maxDepth, out, limit);
  }
}

async function mkdirp(storage: Storage, ref: string): Promise<Node> {
  const m = /^((?:trash|inbox|shares|drive):)?(.*)$/i.exec(ref.trim())!;
  const prefix = m[1] ?? "";
  const parts = m[2].split("/").filter(Boolean);
  let node =
    prefix.toLowerCase() === "shares:"
      ? resolveNode(storage, "shares:/" + (parts.shift() ?? ""))
      : resolveNode(storage, prefix + "/");
  for (const part of parts) {
    const existing = node.children?.find((c) => c.name === part);
    if (existing) {
      node = requireFolder(existing, part);
    } else {
      node = await node.mkdir(part);
    }
  }
  return node;
}

async function uploadLocal(folder: Node, localPath: string, name: string): Promise<Node> {
  const stat = await fs.promises.stat(localPath);
  if (stat.isDirectory()) {
    const existing = folder.children?.find((c) => c.name === name && c.directory);
    const dir = existing ?? (await folder.mkdir(name));
    for (const entry of await fs.promises.readdir(localPath)) {
      await uploadLocal(dir, path.join(localPath, entry), entry);
    }
    return dir;
  }
  const upload = folder.upload({ name, size: stat.size }, undefined) as unknown as NodeJS.WritableStream & {
    complete: Promise<Node>;
  };
  fs.createReadStream(localPath).pipe(upload);
  return upload.complete;
}

async function downloadNode(node: Node | File, localPath: string): Promise<number> {
  if (node.directory) {
    ensureLocalDir(localPath);
    let count = 0;
    for (const child of (node.children ?? []) as (Node | File)[]) {
      count += await downloadNode(child, path.join(localPath, safeName(child.name ?? child.nodeId ?? "unnamed")));
    }
    return count;
  }
  ensureLocalDir(path.dirname(localPath));
  await pipeline(node.download({}), fs.createWriteStream(localPath));
  return 1;
}

function safeName(name: string): string {
  return name.replace(/[\\/]/g, "_").replace(/^\.\.?$/, "_");
}

function encodeBuffer(buf: Buffer, encoding: "utf8" | "base64"): string {
  return encoding === "base64" ? buf.toString("base64") : buf.toString("utf8");
}

async function loadPublic(url: string, subPath?: string): Promise<File> {
  let node = (await File.fromURL(url).loadAttributes()) as File;
  for (const part of (subPath ?? "").split("/").filter(Boolean)) {
    const child = node.children?.find((c) => c.name === part);
    if (!child) throw new Error(`"${part}" not found inside shared folder`);
    node = child;
  }
  return node;
}

export function registerTools(server: McpServer, session: MegaSession): void {
  // ---------------------------------------------------------------- account
  server.registerTool(
    "mega_login",
    {
      title: "Login to MEGA",
      description:
        "Log in (or re-log in) to a MEGA account. Without arguments uses MEGA_EMAIL / MEGA_PASSWORD / MEGA_2FA_CODE env vars. " +
        "Other tools log in automatically, so call this only to switch account or to supply a fresh 2FA code.",
      inputSchema: {
        email: z.string().optional(),
        password: z.string().optional(),
        twoFactorCode: z.string().optional().describe("Current 6-digit 2FA code, if the account has 2FA enabled"),
      },
    },
    safe(async ({ email, password, twoFactorCode }) => {
      const s = await session.login({ email, password, secondFactorCode: twoFactorCode });
      return ok({ loggedIn: true, name: s.name, email: s.email, user: s.user });
    })
  );

  server.registerTool(
    "mega_logout",
    { title: "Logout", description: "Close the current MEGA session.", inputSchema: {} },
    safe(async () => {
      await session.logout();
      return ok({ loggedIn: false });
    })
  );

  server.registerTool(
    "mega_account_info",
    {
      title: "Account info",
      description: "Account type, storage quota usage and transfer (bandwidth) quota.",
      inputSchema: {},
    },
    safe(async () => {
      const s = await session.get();
      const info = await s.getAccountInfo();
      return ok({
        name: s.name,
        email: s.email,
        ...info,
        spaceUsedHuman: formatBytes(info.spaceUsed),
        spaceTotalHuman: formatBytes(info.spaceTotal),
        spaceFreeHuman: formatBytes(info.spaceTotal - info.spaceUsed),
      });
    })
  );

  server.registerTool(
    "mega_reload",
    {
      title: "Reload file tree",
      description: "Force a refresh of the cached file tree from MEGA (use after changes made from other clients).",
      inputSchema: {},
    },
    safe(async () => {
      const s = await session.get();
      await s.reload(true);
      return ok({ reloaded: true, nodes: Object.keys(s.files).length });
    })
  );

  // ---------------------------------------------------------------- browse
  server.registerTool(
    "mega_list",
    {
      title: "List folder",
      description: "List the contents of a folder. Set recursive to walk sub-folders.",
      inputSchema: {
        path: remotePath.default("/"),
        recursive: z.boolean().default(false),
        maxDepth: z.number().int().min(0).max(50).default(10).describe("Max depth when recursive"),
        limit: z.number().int().min(1).max(10000).default(500),
      },
    },
    safe(async ({ path: ref, recursive, maxDepth, limit }) => {
      const s = await session.get();
      const node = requireFolder(resolveNode(s, ref), ref);
      const entries: Record<string, unknown>[] = [];
      listTree(node, 0, recursive ? maxDepth : 0, entries, limit);
      return ok({ folder: describe(node), entries, truncated: entries.length >= limit });
    })
  );

  server.registerTool(
    "mega_get_info",
    {
      title: "Get node info",
      description: "Metadata for a file or folder: id, size, modified date, label, favorite, public link status.",
      inputSchema: { path: remotePath },
    },
    safe(async ({ path: ref }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      return ok({ ...describe(node), attributes: node.attributes });
    })
  );

  server.registerTool(
    "mega_search",
    {
      title: "Search",
      description: "Find files/folders by name (case-insensitive substring, or regular expression) under a folder.",
      inputSchema: {
        query: z.string(),
        regex: z.boolean().default(false),
        path: remotePath.default("/").describe("Folder to search in (recursively). " + PATH_HELP),
        type: z.enum(["any", "file", "folder"]).default("any"),
        limit: z.number().int().min(1).max(5000).default(200),
      },
    },
    safe(async ({ query, regex, path: ref, type, limit }) => {
      const s = await session.get();
      const base = requireFolder(resolveNode(s, ref), ref);
      const re = regex ? new RegExp(query, "i") : null;
      const q = query.toLowerCase();
      const matches: Record<string, unknown>[] = [];
      const visit = (node: Node): void => {
        for (const f of node.children ?? []) {
          if (matches.length >= limit) return;
          const name = f.name ?? "";
          const typeOk = type === "any" || (type === "folder") === Boolean(f.directory);
          if (typeOk && (re ? re.test(name) : name.toLowerCase().includes(q))) matches.push(describe(f));
          if (f.directory) visit(f);
        }
      };
      visit(base);
      return ok({ count: matches.length, results: matches });
    })
  );

  server.registerTool(
    "mega_list_shares",
    {
      title: "List shares",
      description: "List incoming shares (folders other users shared with you) and your own nodes exported with a public link.",
      inputSchema: {},
    },
    safe(async () => {
      const s = await session.get();
      const incoming = incomingShares(s).map((n) => describe(n));
      const exported = Object.values(s.files)
        .filter((f) => (f as Node & { shared?: boolean }).shared)
        .map((n) => describe(n));
      return ok({ incoming, publicLinks: exported });
    })
  );

  // ---------------------------------------------------------------- modify
  server.registerTool(
    "mega_mkdir",
    {
      title: "Create folder",
      description: "Create a folder. With parents=true, missing intermediate folders are created too (like mkdir -p).",
      inputSchema: { path: remotePath, parents: z.boolean().default(true) },
    },
    safe(async ({ path: ref, parents }) => {
      const s = await session.get();
      if (parents) return ok(describe(await mkdirp(s, ref)));
      const { parent, name } = splitParent(ref);
      const folder = requireFolder(resolveNode(s, parent), parent);
      return ok(describe(await folder.mkdir(name)));
    })
  );

  server.registerTool(
    "mega_rename",
    {
      title: "Rename",
      description: "Rename a file or folder (stays in the same folder).",
      inputSchema: { path: remotePath, newName: z.string().min(1) },
    },
    safe(async ({ path: ref, newName }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      await node.rename(newName);
      return ok(describe(node));
    })
  );

  server.registerTool(
    "mega_move",
    {
      title: "Move",
      description: "Move a file or folder into another folder (also used to restore items from trash:/).",
      inputSchema: { path: remotePath, destination: remotePath.describe("Destination folder. " + PATH_HELP) },
    },
    safe(async ({ path: ref, destination }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      const target = requireFolder(resolveNode(s, destination), destination);
      await node.moveTo(target);
      return ok({ moved: true, ...describe(node), path: nodePath(target) + "/" + node.name });
    })
  );

  server.registerTool(
    "mega_copy",
    {
      title: "Copy",
      description: "Server-side copy of a file or folder into another folder (no data is downloaded).",
      inputSchema: { path: remotePath, destination: remotePath.describe("Destination folder. " + PATH_HELP) },
    },
    safe(async ({ path: ref, destination }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      const target = requireFolder(resolveNode(s, destination), destination);
      await node.copyTo(target);
      return ok({ copied: true, source: nodePath(node), destination: nodePath(target) });
    })
  );

  server.registerTool(
    "mega_delete",
    {
      title: "Delete",
      description: "Delete a file or folder. By default it is moved to the Rubbish Bin; permanent=true deletes it forever.",
      inputSchema: { path: remotePath, permanent: z.boolean().default(false) },
      annotations: { destructiveHint: true },
    },
    safe(async ({ path: ref, permanent }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      if (node === s.root || node === s.trash || node === s.inbox) throw new Error("Cannot delete a root folder");
      const info = describe(node);
      await node.delete(permanent);
      return ok({ deleted: true, permanent, ...info });
    })
  );

  server.registerTool(
    "mega_empty_trash",
    {
      title: "Empty Rubbish Bin",
      description: "Permanently delete everything in the Rubbish Bin.",
      inputSchema: {},
      annotations: { destructiveHint: true },
    },
    safe(async () => {
      const s = await session.get();
      const items = [...(s.trash.children ?? [])];
      for (const item of items) await item.delete(true);
      return ok({ deleted: items.length });
    })
  );

  server.registerTool(
    "mega_set_label",
    {
      title: "Set color label",
      description: "Set (or clear with 'none') the color label of a file/folder.",
      inputSchema: {
        path: remotePath,
        label: z.enum(["none", "red", "orange", "yellow", "green", "blue", "purple", "grey"]),
      },
    },
    safe(async ({ path: ref, label }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      await node.setLabel(label === "none" ? "" : label);
      return ok(describe(node));
    })
  );

  server.registerTool(
    "mega_set_favorite",
    {
      title: "Set favorite",
      description: "Mark or unmark a file/folder as favorite.",
      inputSchema: { path: remotePath, favorite: z.boolean().default(true) },
    },
    safe(async ({ path: ref, favorite }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      await node.setFavorite(favorite);
      return ok(describe(node));
    })
  );

  // ---------------------------------------------------------------- transfer
  server.registerTool(
    "mega_upload",
    {
      title: "Upload local file/folder",
      description: "Upload a local file or a whole local directory (recursively) into a MEGA folder.",
      inputSchema: {
        localPath: z.string().describe("Path on the machine running this MCP server"),
        remoteFolder: remotePath.default("/").describe("Destination folder (created if missing). " + PATH_HELP),
        name: z.string().optional().describe("Name to use on MEGA (defaults to the local name)"),
      },
    },
    safe(async ({ localPath, remoteFolder, name }) => {
      const s = await session.get();
      const local = resolveLocal(localPath);
      const folder = await mkdirp(s, remoteFolder);
      const node = await uploadLocal(folder, local, name ?? path.basename(local));
      return ok({ uploaded: true, ...describe(node) });
    })
  );

  server.registerTool(
    "mega_write_file",
    {
      title: "Write file from content",
      description: "Create a file on MEGA from text or base64 content. MEGA has no in-place edit: an existing file with the same name is replaced only if overwrite=true.",
      inputSchema: {
        path: remotePath.describe("Full remote path of the file to create. " + PATH_HELP),
        content: z.string(),
        encoding: z.enum(["utf8", "base64"]).default("utf8"),
        overwrite: z.boolean().default(false),
      },
    },
    safe(async ({ path: ref, content, encoding, overwrite }) => {
      const s = await session.get();
      const { parent, name } = splitParent(ref);
      const folder = await mkdirp(s, parent);
      const existing = folder.children?.find((c) => c.name === name && !c.directory);
      if (existing && !overwrite) throw new Error(`"${ref}" already exists (set overwrite=true to replace it)`);
      const data = Buffer.from(content, encoding === "base64" ? "base64" : "utf8");
      const upload = folder.upload({ name, size: data.length }, data) as unknown as { complete: Promise<Node> };
      const node = await upload.complete;
      if (existing) await existing.delete(false);
      return ok({ written: true, ...describe(node) });
    })
  );

  server.registerTool(
    "mega_download",
    {
      title: "Download to local disk",
      description: "Download a file, or a folder recursively, from MEGA to the local filesystem.",
      inputSchema: {
        path: remotePath,
        localPath: z.string().describe("Destination on the local machine. For a file, a directory path saves it inside that directory."),
      },
    },
    safe(async ({ path: ref, localPath }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      let dest = resolveLocal(localPath);
      if (!node.directory && fs.existsSync(dest) && fs.statSync(dest).isDirectory()) {
        dest = path.join(dest, safeName(node.name ?? "download"));
      }
      const files = await downloadNode(node, dest);
      return ok({ downloaded: true, files, localPath: dest });
    })
  );

  server.registerTool(
    "mega_read_file",
    {
      title: "Read file content",
      description: "Download a file (or a byte range of it) and return its content as text or base64.",
      inputSchema: {
        path: remotePath,
        encoding: z.enum(["utf8", "base64"]).default("utf8"),
        start: z.number().int().min(0).default(0),
        maxBytes: z.number().int().min(1).max(50 * 1024 * 1024).default(1024 * 1024),
      },
    },
    safe(async ({ path: ref, encoding, start, maxBytes }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      if (node.directory) throw new Error(`"${ref}" is a folder`);
      const size = node.size ?? 0;
      if (size === 0) return ok({ ...describe(node), content: "" });
      if (start >= size) throw new Error(`start (${start}) is beyond the end of the file (${size} bytes)`);
      const end = Math.min(size, start + maxBytes) - 1;
      const buf = await node.downloadBuffer({ start, end });
      return ok({ ...describe(node), range: [start, end], truncated: end < size - 1, encoding, content: encodeBuffer(buf, encoding) });
    })
  );

  // ---------------------------------------------------------------- sharing
  server.registerTool(
    "mega_create_link",
    {
      title: "Create public link",
      description: "Export a file or folder with a public link (mega.nz/file/... or mega.nz/folder/...). Returns the existing link if already exported.",
      inputSchema: {
        path: remotePath,
        includeKey: z.boolean().default(true).describe("Include the decryption key in the URL (#key). If false, share the key separately."),
        folderKey: z.string().optional().describe("Optional 22-char base64 share key to use for a folder link"),
      },
    },
    safe(async ({ path: ref, includeKey, folderKey }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      const url = await node.link({ noKey: !includeKey, ...(folderKey ? { key: folderKey } : {}) });
      const key = url.includes("#") ? undefined : node.directory ? undefined : node.key?.toString("base64url");
      return ok({ url, ...(key ? { key } : {}), ...describe(node) });
    })
  );

  server.registerTool(
    "mega_remove_link",
    {
      title: "Remove public link",
      description: "Disable the public link of a file or folder.",
      inputSchema: { path: remotePath },
    },
    safe(async ({ path: ref }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      await node.unshare();
      return ok({ unshared: true, ...describe(node) });
    })
  );

  server.registerTool(
    "mega_set_thumbnail",
    {
      title: "Set thumbnail/preview",
      description: "Upload a JPEG image as thumbnail (120x120) or preview of a file.",
      inputSchema: {
        path: remotePath,
        imagePath: z.string().describe("Local JPEG image path"),
        kind: z.enum(["thumbnail", "preview"]).default("thumbnail"),
      },
    },
    safe(async ({ path: ref, imagePath, kind }) => {
      const s = await session.get();
      const node = resolveNode(s, ref);
      await node.uploadAttribute(kind, await fs.promises.readFile(resolveLocal(imagePath)));
      return ok({ updated: true, kind, ...describe(node) });
    })
  );

  // ---------------------------------------------------------------- public links (no login needed)
  server.registerTool(
    "mega_public_info",
    {
      title: "Inspect public link",
      description: "Read metadata of a public MEGA link (file or folder). For folders, lists the contents. Does not require login.",
      inputSchema: {
        url: z.string().describe("https://mega.nz/file/...#key or https://mega.nz/folder/...#key"),
        subPath: z.string().optional().describe("Path inside a shared folder"),
        recursive: z.boolean().default(false),
        limit: z.number().int().min(1).max(10000).default(500),
      },
    },
    safe(async ({ url, subPath, recursive, limit }) => {
      const node = await loadPublic(url, subPath);
      const result: Record<string, unknown> = describe(node, false);
      if (node.directory) {
        const entries: Record<string, unknown>[] = [];
        listTree(node, 0, recursive ? 50 : 0, entries, limit);
        result.entries = entries.map((e) => ({ ...e, path: undefined }));
      }
      return ok(result);
    })
  );

  server.registerTool(
    "mega_public_download",
    {
      title: "Download public link",
      description: "Download a public MEGA file or folder link (optionally a sub-path of a folder) to the local filesystem. Does not require login.",
      inputSchema: {
        url: z.string(),
        subPath: z.string().optional(),
        localPath: z.string().describe("Destination file or directory on the local machine"),
      },
    },
    safe(async ({ url, subPath, localPath }) => {
      const node = await loadPublic(url, subPath);
      let dest = resolveLocal(localPath);
      if (!node.directory && fs.existsSync(dest) && fs.statSync(dest).isDirectory()) {
        dest = path.join(dest, safeName(node.name ?? "download"));
      }
      const files = await downloadNode(node, dest);
      return ok({ downloaded: true, files, localPath: dest });
    })
  );

  server.registerTool(
    "mega_public_read",
    {
      title: "Read public file",
      description: "Return the content of a file behind a public MEGA link as text or base64. Does not require login.",
      inputSchema: {
        url: z.string(),
        subPath: z.string().optional(),
        encoding: z.enum(["utf8", "base64"]).default("utf8"),
        maxBytes: z.number().int().min(1).max(50 * 1024 * 1024).default(1024 * 1024),
      },
    },
    safe(async ({ url, subPath, encoding, maxBytes }) => {
      const node = await loadPublic(url, subPath);
      if (node.directory) throw new Error("Link points to a folder: pass subPath to pick a file");
      const size = node.size ?? 0;
      const end = Math.min(size, maxBytes) - 1;
      const buf = size === 0 ? Buffer.alloc(0) : await node.downloadBuffer({ start: 0, end });
      return ok({ ...describe(node, false), truncated: end < size - 1, encoding, content: encodeBuffer(buf, encoding) });
    })
  );

  server.registerTool(
    "mega_import_link",
    {
      title: "Import public link",
      description: "Import (save) a file from a public MEGA link into your own account, server-side. For folder links, all files are imported recursively, recreating the folder structure.",
      inputSchema: {
        url: z.string(),
        remoteFolder: remotePath.default("/").describe("Destination folder (created if missing). " + PATH_HELP),
      },
    },
    safe(async ({ url, remoteFolder }) => {
      const s = await session.get();
      const target = await mkdirp(s, remoteFolder);
      const source = await loadPublic(url);
      let imported = 0;
      const importInto = async (src: File, dest: Node): Promise<Node> => {
        if (!src.directory) {
          imported++;
          return dest.importFile(src);
        }
        const dir = await dest.mkdir(src.name ?? "folder");
        for (const child of src.children ?? []) await importInto(child, dir);
        return dir;
      };
      const node = await importInto(source, target);
      return ok({ imported, ...describe(node) });
    })
  );

  // ---------------------------------------------------------------- advanced
  server.registerTool(
    "mega_api_request",
    {
      title: "Raw MEGA API request",
      description:
        "Advanced: send a raw command to the MEGA API (https://g.api.mega.co.nz/cs) using the current session, e.g. {\"a\":\"uq\",\"strg\":1}. " +
        "Use only for operations not covered by other tools; most node data is encrypted and returned as-is.",
      inputSchema: {
        request: z.record(z.string(), z.unknown()).describe('API command object, must contain "a" (the action)'),
      },
      annotations: { destructiveHint: true },
    },
    safe(async ({ request }) => {
      if (typeof request.a !== "string") throw new Error('request must contain an "a" string field');
      const s = await session.get();
      const response = await s.api.request(request as never);
      return ok(response);
    })
  );
}
