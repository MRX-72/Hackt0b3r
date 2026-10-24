"use strict";
// Colour theme: dark (default), grey (the earlier softer palette) or light. The choice is kept in
// this browser only. Loaded in <head> so the theme is set before the first paint.
(() => {
  const THEMES = ["dark", "grey", "light"], KEY = "sentinel-theme";
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch (_) { /* storage blocked: stay on the default */ }
  const first = THEMES.includes(saved) ? saved : "dark";
  document.documentElement.dataset.theme = first;
  const apply = (name) => {
    document.documentElement.dataset.theme = name;
    document.querySelectorAll("#theme button").forEach((b) => b.classList.toggle("on", b.dataset.v === name));
    document.dispatchEvent(new CustomEvent("sentinel:theme", { detail: name }));
  };
  document.addEventListener("DOMContentLoaded", () => {
    apply(first);
    document.querySelectorAll("#theme button").forEach((b) => b.addEventListener("click", () => {
      apply(b.dataset.v);
      try { localStorage.setItem(KEY, b.dataset.v); } catch (_) { /* not saved, still applied */ }
    }));
  });
})();
