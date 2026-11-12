// Local names and notes for peers, stored as [[note]] tables in this node's configuration.
import { apply, configured } from "./config";

export interface Note {
  peer: string;
  name?: string;
  text?: string;
}

export const notes = (): Note[] => ((configured("note") ?? []) as Note[]).map((note) => ({ ...note }));

export function noteFor(key: string): Note | undefined {
  return key ? notes().find((note) => note.peer === key) : undefined;
}

/** The local name for a peer key, or nothing when the peer keeps its own hostname. */
export const aliasFor = (key: string) => noteFor(key)?.name?.trim() || undefined;

/** Replace the note for one peer. Empty name and text remove the entry. */
export function saveNote(key: string, change: { name?: string; text?: string }) {
  const current = noteFor(key) ?? { peer: key };
  const next: Note = { peer: key };
  const name = (change.name ?? current.name ?? "").trim();
  const text = (change.text ?? current.text ?? "").trim();
  if (name) next.name = name;
  if (text) next.text = text;
  const rest = notes().filter((note) => note.peer !== key);
  if (next.name || next.text) rest.push(next);
  return apply({ note: rest.length ? rest : null });
}
