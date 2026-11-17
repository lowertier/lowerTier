import { For, Show, createUniqueId } from "solid-js";
import { RETENTION_PERIODS, type MachineType } from "../retention";

export default function RetentionOptions(props: {
  type: MachineType;
  period: number;
  onType: (value: MachineType) => void;
  onPeriod: (value: number) => void;
}) {
  const id = createUniqueId();
  const choices: { value: MachineType; label: string; description: string }[] = [
    { value: "temporary", label: "Temporary", description: "For VMs and containers. Remove the record when the machine goes offline." },
    { value: "retained", label: "Keep for a period", description: "Show the last online time while the machine is offline." },
    { value: "permanent", label: "Keep until removed", description: "For machines that can stay offline for a long time." },
  ];
  return (
    <fieldset class="retention-options">
      <legend>Offline retention</legend>
      <For each={choices}>
        {(choice) => (
          <div class="choice">
            <input
              id={`${id}-${choice.value}`}
              type="radio"
              name={`${id}-retention`}
              value={choice.value}
              checked={props.type === choice.value}
              onChange={() => props.onType(choice.value)}
              aria-describedby={`${id}-${choice.value}-help`}
            />
            <label for={`${id}-${choice.value}`}>
              <b>{choice.label}</b>
              <span class="sub" id={`${id}-${choice.value}-help`}>{choice.description}</span>
            </label>
          </div>
        )}
      </For>
      <Show when={props.type === "retained"}>
        <div class="field retention-period">
          <label for={`${id}-period`}>Remove after being offline for</label>
          <select id={`${id}-period`} name="retention-period" value={props.period} onChange={(event) => props.onPeriod(Number(event.currentTarget.value))}>
            <Show when={!RETENTION_PERIODS.some((period) => period.seconds === props.period)}>
              <option value={props.period}>{props.period} seconds</option>
            </Show>
            <For each={RETENTION_PERIODS}>
              {(period) => <option value={period.seconds}>{period.label}</option>}
            </For>
          </select>
        </div>
      </Show>
    </fieldset>
  );
}
