// Auto follows the system setting; Light and Night override it and persist in this browser.
import { createSignal } from "solid-js";

export const THEMES = ["Auto", "Light", "Night"] as const;
export type Theme = (typeof THEMES)[number];
const STORAGE = "lowertier-theme";

function stored(): Theme {
  try {
    const value = localStorage.getItem(STORAGE);
    return (THEMES as readonly string[]).includes(value ?? "") ? (value as Theme) : "Auto";
  } catch {
    return "Auto";
  }
}

function paint(theme: Theme) {
  const root = document.documentElement;
  if (theme === "Auto") root.removeAttribute("data-theme");
  else root.dataset.theme = theme === "Night" ? "dark" : "light";
}

const [theme, setThemeSignal] = createSignal<Theme>(stored());
paint(theme());

export { theme };

export function setTheme(next: Theme) {
  setThemeSignal(next);
  paint(next);
  try {
    if (next === "Auto") localStorage.removeItem(STORAGE);
    else localStorage.setItem(STORAGE, next);
  } catch {}
}
