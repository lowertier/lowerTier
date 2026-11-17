import { createSignal } from "solid-js";
import { Dialog } from "../components/controls";
import RetentionOptions from "../components/RetentionOptions";
import { busy } from "../config";
import { saveNote } from "../notes";
import { DEFAULT_RETENTION, machineType, retentionSeconds } from "../retention";
import { restart, type PeerRow } from "../store";

export default function MachineRetention(props: { row: PeerRow; onClose: () => void }) {
  const [type, setType] = createSignal(machineType(props.row.retention));
  const [period, setPeriod] = createSignal(props.row.retention > 0 ? props.row.retention : DEFAULT_RETENTION);
  let close = props.onClose;
  const save = async () => {
    if (await saveNote(props.row.key, { offline_retention: retentionSeconds(type(), period()) })) {
      restart();
      close();
    }
  };
  return (
    <Dialog title={`Offline retention for ${props.row.name}`} onClose={props.onClose}>
      <form
        class="edit-form"
        method="post"
        aria-label="Machine retention"
        ref={(form) => { close = () => form.closest("dialog")?.close(); }}
        onSubmit={(event) => { event.preventDefault(); save(); }}
      >
        <p class="hint">This setting controls the record on this node. It does not revoke network access.</p>
        <RetentionOptions type={type()} period={period()} onType={setType} onPeriod={setPeriod} />
        <div class="dialog-actions">
          <button type="submit" class="primary" disabled={busy()}>{busy() ? "Saving…" : "Save retention"}</button>
          <button type="button" class="link" onClick={() => close()}>Cancel</button>
        </div>
      </form>
    </Dialog>
  );
}
