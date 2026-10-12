// Light and dark console themes. The theme lives on <html data-theme>, set by
// THEME_SCRIPT before first paint so the page never flashes the wrong colours.
// An explicit choice is remembered in this browser; without one the console
// follows the system setting, including when it changes.

export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "argus-theme";

// Inline in the root layout's <head>; the CSP allows inline scripts.
export const THEME_SCRIPT = `(function(){try{var t=localStorage.getItem("${THEME_STORAGE_KEY}");if(t!=="light"&&t!=="dark")t=matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";document.documentElement.dataset.theme=t}catch(e){}})()`;

export function storedTheme(): Theme | null {
  try {
    const value = localStorage.getItem(THEME_STORAGE_KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

export function storeTheme(theme: Theme) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {}
}

export function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
}
