"use client";
import { useSyncExternalStore } from "react";
import { MoonIcon, SunIcon } from "@/components/icons";
import { applyTheme, storeTheme, storedTheme, type Theme } from "@/lib/theme";

// The theme is read from <html data-theme> (set by THEME_SCRIPT), so every
// toggle on the page stays in step. Until the user picks a theme here, the
// console follows the system setting when it changes.
function subscribe(onChange: () => void) {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  const media = window.matchMedia("(prefers-color-scheme: light)");
  const onSystemChange = () => {
    if (!storedTheme()) applyTheme(media.matches ? "light" : "dark");
  };
  media.addEventListener("change", onSystemChange);
  return () => {
    observer.disconnect();
    media.removeEventListener("change", onSystemChange);
  };
}

const currentTheme = (): Theme =>
  document.documentElement.dataset.theme === "light" ? "light" : "dark";

export function ThemeToggle({ className = "" }: { className?: string }) {
  // Null on the server, which cannot know the theme THEME_SCRIPT picked.
  const theme = useSyncExternalStore<Theme | null>(subscribe, currentTheme, () => null);
  const next: Theme = theme === "light" ? "dark" : "light";
  return (
    <button
      type="button"
      onClick={() => {
        applyTheme(next);
        storeTheme(next);
      }}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      className={`grid size-7 place-items-center rounded-sm border border-line-strong text-ink-2 transition hover:border-accent hover:text-accent ${className}`}
    >
      {theme === "light" ? <MoonIcon className="size-3.5" /> : <SunIcon className="size-3.5" />}
    </button>
  );
}
