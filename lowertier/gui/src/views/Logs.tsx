import { For, Show, createEffect, createMemo, createSignal, on, onCleanup, onMount } from "solid-js";
import { ApiError, rpc, type Doc } from "../api";
import { Segmented } from "../components/controls";
import { say } from "../config";
import { clock } from "../format";
import { selection } from "../store";

const KEEP = 2000;
const LEVELS = ["error", "warn", "info", "debug", "trace"];

export default function Logs() {
  const [lines, setLines] = createSignal<Doc[]>([]);
  const [level, setLevel] = createSignal("info");
  const [daemonLevel, setDaemonLevel] = createSignal<string>();
  const [filter, setFilter] = createSignal("");
  const [follow, setFollow] = createSignal(true);
  const [clearing, setClearing] = createSignal(false);
  const [failure, setFailure] = createSignal("");
  let cursor = "";
  let timer: number | undefined;
  let box: HTMLDivElement | undefined;
  let stopped = false;

  const read = async () => {
    try {
      for (let page = 0; page < 8; page++) {
        const response = await rpc("ReadLogs", { page: { limit: 256, page_token: cursor } });
        const logs = (response.logs ?? []) as Doc[];
        if (response.next_page_token) cursor = response.next_page_token;
        if (logs.length) setLines((current) => [...current, ...logs].slice(-KEEP));
        if (logs.length < 256) break;
      }
      setFailure("");
    } catch (caught) {
      // A restarted daemon rejects the old cursor: read its log from the start.
      if (caught instanceof ApiError && caught.field === "page.page_token") cursor = "";
      setFailure(caught instanceof Error ? caught.message : String(caught));
    }
    if (follow() && box) box.scrollTop = box.scrollHeight;
    if (!stopped) timer = window.setTimeout(read, document.hidden ? 5000 : 1000);
  };

  // Each daemon has its own log and cursor.
  createEffect(
    on(
      selection,
      () => {
        cursor = "";
        setLines([]);
        rpc("GetLogConfig")
          .then((response) => setDaemonLevel(response.level))
          .catch(() => setDaemonLevel(undefined));
      },
      { defer: true },
    ),
  );

  onMount(() => {
    read();
    rpc("GetLogConfig")
      .then((response) => setDaemonLevel(response.level))
      .catch(() => {});
  });
  onCleanup(() => {
    stopped = true;
    window.clearTimeout(timer);
  });

  const shown = createMemo(() => {
    const limit = LEVELS.indexOf(level());
    const query = filter().trim().toLowerCase();
    return lines().filter((line) => {
      const rank = LEVELS.indexOf(String(line.level).toLowerCase());
      if (rank > limit) return false;
      return !query || `${line.target} ${line.message}`.toLowerCase().includes(query);
    });
  });

  const changeDaemonLevel = async (value: string) => {
    try {
      await rpc("SetLogConfig", { level: value });
      setDaemonLevel(value);
      say(`The daemon now logs at ${value}.`);
    } catch (caught) {
      say(caught instanceof Error ? caught.message : String(caught), true);
    }
  };

  const clearLogs = async () => {
    setClearing(true);
    try {
      await rpc("ClearLogs");
      cursor = "";
      setLines([]);
      setFailure("");
      say("Logs cleared.");
    } catch (caught) {
      say(caught instanceof Error ? caught.message : String(caught), true);
    } finally {
      setClearing(false);
    }
  };

  return (
    <div class="stack logs-view">
      <div class="toolbar">
        <Segmented label="Show levels up to" values={LEVELS} value={level()} onChange={setLevel} />
        <input type="search" placeholder="Filter" aria-label="Filter logs" value={filter()} onInput={(event) => setFilter(event.currentTarget.value)} />
        <label class="check">
          <input type="checkbox" checked={follow()} onChange={(event) => setFollow(event.currentTarget.checked)} /> Follow
        </label>
        <label class="field compact">
          <span>Daemon level</span>
          <select aria-label="Daemon log level" value={daemonLevel() ?? ""} onChange={(event) => changeDaemonLevel(event.currentTarget.value)}>
            <Show when={!daemonLevel()}>
              <option value="">unknown</option>
            </Show>
            <For each={["off", ...LEVELS]}>{(value) => <option value={value}>{value}</option>}</For>
          </select>
        </label>
        <button type="button" class="quiet" disabled={clearing()} onClick={clearLogs}>
          {clearing() ? "Clearing…" : "Clear logs"}
        </button>
      </div>
      <Show when={failure()}>
        <p class="hint bad">{failure()}</p>
      </Show>
      <div class="panel log-box" ref={box} onWheel={() => box && setFollow(box.scrollTop + box.clientHeight >= box.scrollHeight - 4)}>
        <For each={shown()} fallback={<p class="empty">No log lines at this level.</p>}>
          {(line) => (
            <div classList={{ line: true, [String(line.level).toLowerCase()]: true }}>
              <time>{clock(line.sampled_at_unix_ms)}</time>
              <span class="level">{String(line.level).toLowerCase()}</span>
              <span class="source">{line.target}</span>
              <span class="message">{String(line.message ?? "").replace(/^message=/, "").trimEnd()}</span>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}
