import fs from "node:fs";
import path from "node:path";
import { Storage, File, type MutableFile } from "megajs";

export type Node = MutableFile;

export interface Credentials {
  email: string;
  password: string;
  secondFactorCode?: string;
}

/**
 * Holds the authenticated MEGA session. Login is lazy: it happens on the first
 * tool call that needs the account, using env vars or explicit credentials.
 */
export class MegaSession {
  private storage: Storage | null = null;
  private pending: Promise<Storage> | null = null;

  get isLoggedIn(): boolean {
    return this.storage !== null && this.storage.status === "ready";
  }

  async login(creds?: Partial<Credentials>): Promise<Storage> {
    const email = creds?.email ?? process.env.MEGA_EMAIL;
    const password = creds?.password ?? process.env.MEGA_PASSWORD;
    const secondFactorCode = creds?.secondFactorCode ?? process.env.MEGA_2FA_CODE;
    if (!email || !password) {
      throw new Error(
        "MEGA credentials missing: set MEGA_EMAIL and MEGA_PASSWORD or call mega_login with email/password."
      );
    }
    await this.logout();
    const storage = new Storage({
      email,
      password,
      secondFactorCode: secondFactorCode || undefined,
      keepalive: true,
      autologin: true,
      autoload: true,
    });
    this.pending = storage.ready.then(() => storage);
    try {
      this.storage = await this.pending;
      return this.storage;
    } finally {
      this.pending = null;
    }
  }

  async get(): Promise<Storage> {
    if (this.storage && this.storage.status !== "closed") return this.storage;
    if (this.pending) return this.pending;
    return this.login();
  }

  async logout(): Promise<void> {
    if (this.storage) {
      const s = this.storage;
      this.storage = null;
      await s.close().catch(() => undefined);
    }
  }
}

const NODE_HANDLE = /^[A-Za-z0-9_-]{8}$/;

/** Nodes shared with the user by other accounts (no parent inside the user's tree). */
export function incomingShares(storage: Storage): Node[] {
  const special = new Set([storage.root, storage.trash, storage.inbox].filter(Boolean).map((n) => n.nodeId));
  return Object.values(storage.files).filter(
    (f) => !f.parent && !special.has(f.nodeId) && f.name != null
  );
}

/**
 * Resolves a remote reference to a node. Accepted forms:
 *   "/" or "" -> Cloud Drive root;  "/a/b" -> path inside Cloud Drive
 *   "trash:/a" -> Rubbish Bin;  "inbox:/a" -> Inbox;  "shares:/<share>/a" -> incoming shares
 *   "id:<handle>" or a bare 8-char node handle -> node by id
 */
export function resolveNode(storage: Storage, ref: string): Node {
  const trimmed = (ref ?? "").trim();
  if (trimmed.startsWith("id:") || (NODE_HANDLE.test(trimmed) && storage.files[trimmed])) {
    const id = trimmed.replace(/^id:/, "");
    const node = storage.files[id];
    if (!node) throw new Error(`No node with id "${id}"`);
    return node;
  }

  let base: Node;
  let rest = trimmed;
  const m = /^(trash|inbox|shares|drive):(.*)$/i.exec(trimmed);
  if (m) {
    const scope = m[1].toLowerCase();
    rest = m[2];
    if (scope === "trash") base = storage.trash;
    else if (scope === "inbox") base = storage.inbox;
    else if (scope === "drive") base = storage.root;
    else {
      const parts = splitPath(rest);
      if (parts.length === 0) throw new Error('Specify a share name, e.g. "shares:/ShareName/sub"');
      const share = incomingShares(storage).find((s) => s.name === parts[0]);
      if (!share) throw new Error(`Incoming share "${parts[0]}" not found`);
      return walk(share, parts.slice(1), ref);
    }
  } else {
    base = storage.root;
  }
  if (!base) throw new Error(`Location for "${ref}" is not available`);
  return walk(base, splitPath(rest), ref);
}

function splitPath(p: string): string[] {
  return p.split("/").filter((s) => s.length > 0 && s !== ".");
}

function walk(start: Node, parts: string[], original: string): Node {
  let node = start;
  for (const part of parts) {
    if (part === "..") {
      if (!node.parent) throw new Error(`Path "${original}" goes above its root`);
      node = node.parent;
      continue;
    }
    const child = node.children?.find((c) => c.name === part);
    if (!child) throw new Error(`Path not found: "${original}" (missing "${part}")`);
    node = child;
  }
  return node;
}

/** Splits "/a/b/c" into parent ref "/a/b" and name "c", keeping any scope prefix. */
export function splitParent(ref: string): { parent: string; name: string } {
  const m = /^((?:trash|inbox|shares|drive):)?(.*)$/i.exec(ref.trim())!;
  const prefix = m[1] ?? "";
  const parts = splitPath(m[2]);
  const name = parts.pop();
  if (!name) throw new Error(`"${ref}" has no final name component`);
  return { parent: prefix + "/" + parts.join("/"), name };
}

export function nodePath(node: Node): string {
  const names: string[] = [];
  let cur: Node | undefined = node;
  let top: Node | undefined;
  while (cur) {
    top = cur;
    if (cur.parent) names.unshift(cur.name ?? cur.nodeId ?? "?");
    cur = cur.parent;
  }
  const storage = node.storage;
  let prefix = "";
  if (top === storage.trash) prefix = "trash:";
  else if (top === storage.inbox) prefix = "inbox:";
  else if (top !== storage.root && top) {
    prefix = "shares:";
    names.unshift(top.name ?? top.nodeId ?? "?");
  }
  return prefix + "/" + names.join("/");
}

const LABELS = ["", "red", "orange", "yellow", "green", "blue", "purple", "grey"];

export function describe(node: Node | File, withPath = true): Record<string, unknown> {
  const n = node as Node & { shared?: boolean; shareURL?: string; shareId?: string };
  const out: Record<string, unknown> = {
    name: n.name,
    nodeId: n.nodeId,
    type: n.directory ? "folder" : "file",
  };
  if (withPath && "storage" in n && n.storage) out.path = nodePath(n);
  if (!n.directory) out.size = n.size;
  if (n.directory && n.children) out.childCount = n.children.length;
  if (n.timestamp) out.modified = new Date(n.timestamp * 1000).toISOString();
  if (n.label) out.label = LABELS[Number(n.label)] ?? n.label;
  if (n.favorited) out.favorite = true;
  if (n.shared) {
    out.shared = true;
    if (n.shareURL) out.shareURL = n.shareURL;
  }
  if (n.owner) out.owner = n.owner;
  return out;
}

/** Optional sandbox for local filesystem access (MEGA_LOCAL_ROOT). */
export function resolveLocal(p: string): string {
  const root = process.env.MEGA_LOCAL_ROOT;
  const abs = root ? path.resolve(root, p) : path.resolve(p);
  if (root) {
    const rel = path.relative(path.resolve(root), abs);
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
      throw new Error(`Local path "${p}" is outside MEGA_LOCAL_ROOT (${root})`);
    }
  }
  return abs;
}

export function ensureLocalDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
}

export function formatBytes(n: number | undefined): string {
  if (n == null) return "?";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}
