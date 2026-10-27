// TOML over HTTP to `lowertier gui`, which forwards calls to the selected daemon.
import { parse, stringify } from "smol-toml";

export type Doc = Record<string, any>;

export class ApiError extends Error {
  code: string;
  field: string;
  constructor(error: Doc) {
    super(error.message || "The request failed.");
    this.code = error.code ?? "internal";
    this.field = error.field_path ?? "";
  }
}

const STORAGE = "lowertier-gui-key";

// The key arrives in the URL fragment, which browsers never send to servers. Keep it for
// reloads of this tab and take it out of the address bar.
function readKey(): string {
  const found = /key=([0-9a-f]+)/.exec(location.hash);
  if (found) {
    try {
      sessionStorage.setItem(STORAGE, found[1]);
    } catch {}
    history.replaceState(null, "", location.pathname);
    return found[1];
  }
  try {
    return sessionStorage.getItem(STORAGE) ?? "";
  } catch {
    return "";
  }
}

const key = readKey();
export const hasKey = key !== "";

let target: { node?: string; instance?: string } = {};
export function setTarget(node?: string, instance?: string) {
  target = { node, instance };
}

export async function api(path: string, body?: Doc): Promise<Doc> {
  const params = new URLSearchParams();
  if (target.node) params.set("node", target.node);
  if (target.instance) params.set("instance", target.instance);
  const query = params.size ? `?${params}` : "";
  let response: Response;
  try {
    response = await fetch(`/api/${path}${query}`, {
      method: body ? "POST" : "GET",
      headers: { "x-lowertier-key": key, "content-type": "application/toml" },
      body: body ? stringify(body) : undefined,
      cache: "no-store",
    });
  } catch {
    throw new ApiError({
      code: "offline",
      message: "lowertier gui stopped. Run it again to reconnect.",
    });
  }
  const text = await response.text();
  let doc: Doc;
  try {
    doc = parse(text, { unsafeKeyBehaviour: "drop" });
  } catch {
    throw new ApiError({ code: "internal", message: text || response.statusText });
  }
  if (!response.ok || doc.error) throw new ApiError(doc.error ?? { message: response.statusText });
  return doc;
}

export const rpc = (method: string, body: Doc = {}) => api(`rpc/${method}`, body);

/** Set options by dotted path; `null` clears an option back to its default. Options that need
 * a restart are staged: live options apply now, the rest wait for an instance restart. */
export async function setOptions(changes: Record<string, unknown>): Promise<Doc> {
  const set: Doc = {};
  const clear: string[] = [];
  for (const [path, value] of Object.entries(changes)) {
    if (value === null) {
      clear.push(path);
      continue;
    }
    const keys = path.split(".");
    let table = set;
    for (const part of keys.slice(0, -1)) table = table[part] ??= {};
    table[keys[keys.length - 1]] = value;
  }
  const body: Doc = { stage: true };
  if (Object.keys(set).length) body.set = set;
  if (clear.length) body.clear = clear;
  return api("config", body);
}

export { stringify as toToml, parse as fromToml };
