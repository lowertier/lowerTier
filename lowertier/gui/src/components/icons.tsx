// House glyphs: two nodes and the path between them, drawn on a 24×16 grid with round caps.

/** Two nodes joined by a stepped path: the lowertier mark. */
export function Mark(props: { size?: number }) {
  const width = () => props.size ?? 24;
  return (
    <svg class="mark" viewBox="0 0 24 16" width={width()} height={(width() * 2) / 3} aria-hidden="true">
      <path d="M4 4h7v8h9" />
      <circle cx="4" cy="4" r="2.6" />
      <circle cx="20" cy="12" r="2.6" />
    </svg>
  );
}

/** How traffic reaches a peer: a straight link, a step through a relay, or a broken link. */
export function LinkGlyph(props: { kind: "direct" | "relayed" | "self" | "down" }) {
  return (
    <svg class={`link-glyph ${props.kind}`} viewBox="0 0 24 12" width="24" height="12" aria-hidden="true">
      {props.kind === "direct" && <path d="M5 6h14" />}
      {props.kind === "relayed" && (
        <>
          <path d="M5 9h5V3h4v6h5" />
          <circle class="hop" cx="12" cy="3" r="1.6" />
        </>
      )}
      {props.kind === "down" && <path d="M5 6h4M15 6h4" />}
      {props.kind !== "self" && (
        <>
          <circle cx="4" cy={props.kind === "relayed" ? 9 : 6} r="2.2" />
          <circle cx="20" cy={props.kind === "relayed" ? 9 : 6} r="2.2" />
        </>
      )}
      {props.kind === "self" && (
        <>
          <circle cx="12" cy="6" r="3.4" />
          <circle class="core" cx="12" cy="6" r="1.2" />
        </>
      )}
    </svg>
  );
}

export function MoreGlyph() {
  return (
    <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" class="glyph">
      <circle cx="3.5" cy="8" r="1.3" />
      <circle cx="8" cy="8" r="1.3" />
      <circle cx="12.5" cy="8" r="1.3" />
    </svg>
  );
}

export function CloseGlyph() {
  return (
    <svg viewBox="0 0 12 12" width="12" height="12" aria-hidden="true" class="glyph stroke">
      <path d="M2 2l8 8M10 2l-8 8" />
    </svg>
  );
}

/** A copy mark: a sheet with a stepped corner, the second sheet implied. */
export function CopyGlyph() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" aria-hidden="true" class="glyph stroke">
      <path d="M4.5 4.5V2.2c0-.4.3-.7.7-.7h6.1c.4 0 .7.3.7.7v6.1c0 .4-.3.7-.7.7H9.5" />
      <rect x="1.5" y="4.5" width="8" height="8" rx="0.8" />
    </svg>
  );
}

export function CheckGlyph() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" aria-hidden="true" class="glyph stroke">
      <path d="M2.5 7.4l3 3 6-6.6" />
    </svg>
  );
}

export function Arrow() {
  return (
    <span class="arrow" aria-hidden="true">
      <svg viewBox="0 0 12 8" width="12" height="8">
        <path d="M0 4h10M7 1l3 3-3 3" />
      </svg>
    </span>
  );
}
