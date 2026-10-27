// Configuration in the public TOML layout, the option registry, and change results.
import { createSignal } from "solid-js";
import { api, ApiError, rpc, setOptions, type Doc } from "./api";

export interface OptionSpec {
  path: string;
  kind: string;
  values: string[];
  type: string;
  apply: string;
  default: string;
  secret: boolean;
  doc: string;
  fields: string[];
}

const [schema, setSchema] = createSignal<OptionSpec[]>([]);
const [config, setConfig] = createSignal<Doc | null>(null);
const [notice, setNotice] = createSignal<{ error: boolean; text: string } | null>(null);
const [busy, setBusy] = createSignal(false);

export { schema, config, notice, busy };

export function spec(path: string): OptionSpec | undefined {
  return schema().find((option) => option.path === path);
}

export function lookup(table: Doc | undefined, path: string): any {
  let value: any = table;
  for (const part of path.split(".")) {
    if (value == null || typeof value !== "object") return undefined;
    value = value[part];
  }
  return value;
}

/** The configured value: staged when a change waits for a restart, active otherwise. */
export function configured(path: string): any {
  const current = config();
  return lookup(current?.desired ?? current?.active, path);
}

export function restartPending(path: string): boolean {
  return ((config()?.restart_fields ?? []) as string[]).includes(path);
}

export async function loadConfig() {
  try {
    setConfig(await api("config"));
  } catch (caught) {
    setConfig(null);
    if (caught instanceof ApiError && caught.code !== "offline") say(caught.message, true);
  }
}

export async function loadSchema() {
  if (schema().length) return;
  try {
    setSchema(((await api("schema")).options ?? []) as OptionSpec[]);
  } catch {}
}

let clearTimer: number | undefined;
export function say(text: string, error = false) {
  setNotice({ text, error });
  window.clearTimeout(clearTimer);
  clearTimer = window.setTimeout(() => setNotice(null), error ? 12000 : 6000);
}

function summary(result: Doc | undefined): { text: string; error: boolean } {
  if (!result) return { text: "Done.", error: false };
  const errors = ((result.errors ?? []) as Doc[]).map((error) => error.message);
  if (errors.length) return { text: errors.join(" "), error: true };
  const parts: string[] = [];
  const list = (fields?: string[]) => (fields ?? []).join(", ");
  if (result.live_fields?.length) parts.push(`Applied now: ${list(result.live_fields)}.`);
  if (result.new_connection_fields?.length) parts.push(`New connections use ${list(result.new_connection_fields)}.`);
  if (result.restart_fields?.length) parts.push(`Waits for an instance restart: ${list(result.restart_fields)}.`);
  return { text: parts.join(" ") || "Done.", error: false };
}

/** Apply option changes by path. `null` resets an option to its default. */
export async function apply(changes: Record<string, unknown>): Promise<boolean> {
  setBusy(true);
  try {
    const response = await setOptions(changes);
    const { text, error } = summary(response.result);
    say(response.unsaved && !error ? `${text} Not saved to a file: ${response.unsaved}` : text, error);
    return !error;
  } catch (caught) {
    say(caught instanceof Error ? caught.message : String(caught), true);
    return false;
  } finally {
    await loadConfig();
    setBusy(false);
  }
}

/** Stop and start the instance so staged options take effect. */
export async function restartInstance(): Promise<void> {
  setBusy(true);
  try {
    await rpc("StopInstance");
    const started = await rpc("StartInstance");
    const errors = ((started.result?.errors ?? []) as Doc[]).map((error) => error.message);
    say(errors.length ? errors.join(" ") : "The instance restarted with the staged options.", errors.length > 0);
  } catch (caught) {
    say(caught instanceof Error ? caught.message : String(caught), true);
  } finally {
    await loadConfig();
    setBusy(false);
  }
}

export interface Preference {
  peer: string;
  via: string;
}

export function preferences(): Preference[] {
  return ((configured("relay.prefer") ?? []) as Preference[]).map((entry) => ({ peer: entry.peer, via: entry.via }));
}

/** Prefer reaching `peer` through `via` as the first hop. `via` undefined restores automatic routing. */
export function preferRoute(peer: string, via?: string) {
  const next = preferences().filter((entry) => entry.peer !== peer);
  if (via) next.push({ peer, via });
  return apply({ "relay.prefer": next.length ? next : null });
}

export interface LinkCost {
  peer: string;
  bias_ms: number;
}

export function linkCosts(): LinkCost[] {
  return ((configured("relay.link_cost") ?? []) as LinkCost[]).map((entry) => ({ peer: entry.peer, bias_ms: entry.bias_ms }));
}

export function setLinkCost(peer: string, bias?: number) {
  const next = linkCosts().filter((entry) => entry.peer !== peer);
  if (bias) next.push({ peer, bias_ms: bias });
  return apply({ "relay.link_cost": next.length ? next : null });
}
