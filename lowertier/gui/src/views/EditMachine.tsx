import { Show, createSignal, onMount } from "solid-js";
import { Dialog } from "../components/controls";
import { apply, busy } from "../config";
import { noteFor, saveNote } from "../notes";
import { peers, snapshot } from "../store";
import { SELF } from "./Machines";

/** Rename a machine and edit its note. Peers get a local alias; this machine changes its hostname. */
export default function EditMachine(props: { id: number; focus: "name" | "text"; onClose: () => void }) {
  const self = props.id === SELF;
  const row = peers().find((peer) => peer.id === props.id);
  const note = row ? noteFor(row.key) : undefined;
  const hostname = self ? (snapshot()?.node?.node?.hostname ?? "") : (row?.hostname ?? "");
  const [name, setName] = createSignal(self ? hostname : (note?.name ?? ""));
  const [text, setText] = createSignal(note?.text ?? "");
  let nameInput: HTMLInputElement | undefined;
  let textInput: HTMLTextAreaElement | undefined;
  let close: () => void = props.onClose;
  onMount(() => queueMicrotask(() => (props.focus === "text" && !self ? textInput : nameInput)?.focus()));

  const save = async () => {
    const done = self ? await apply({ "node.hostname": name().trim() || null }) : await saveNote(row!.key, { name: name(), text: text() });
    if (done) close();
  };

  return (
    <Dialog title={self ? "Rename this machine" : `Edit ${row?.name ?? "machine"}`} onClose={props.onClose}>
      <Show when={self || row} fallback={<p class="empty">This machine left the network.</p>}>
        <form
          class="edit-form"
          ref={(form) => {
            close = () => (form.closest("dialog") as HTMLDialogElement | null)?.close();
          }}
          onSubmit={(event) => {
            event.preventDefault();
            save();
          }}
        >
          <label class="field">
            <span>{self ? "Hostname" : "Name on this machine"}</span>
            <input ref={nameInput} type="text" maxLength={64} value={name()} placeholder={hostname} onInput={(event) => setName(event.currentTarget.value)} />
            <span class="hint">
              {self ? "Peers see this name. It applies now." : `Leave empty to use the machine's own hostname, ${hostname}. Other machines keep their own names.`}
            </span>
          </label>
          <Show when={!self}>
            <label class="field">
              <span>Note</span>
              <textarea ref={textInput} rows={4} maxLength={2000} value={text()} placeholder="Owner, location, purpose…" onInput={(event) => setText(event.currentTarget.value)} />
              <span class="hint">Stored in this machine's configuration as a [[note]] table.</span>
            </label>
          </Show>
          <div class="dialog-actions">
            <button type="submit" class="primary" disabled={busy()}>
              {busy() ? "Saving…" : "Save"}
            </button>
            <button type="button" class="link" onClick={() => close()}>
              Cancel
            </button>
          </div>
        </form>
      </Show>
    </Dialog>
  );
}
