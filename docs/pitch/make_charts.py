"""Renders the three deck charts as PNGs for the Keynote/Google-Slides-safe variant of the deck."""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

NAVY, RED, AMBER, TEAL, STEEL, SLATE = "#0B1B2B", "#E5383B", "#F4A261", "#2EC4B6", "#8D99AE", "#3A506B"
plt.rcParams.update({"font.family": "DejaVu Sans", "axes.edgecolor": "#C9D2DC", "axes.labelcolor": NAVY,
                     "xtick.color": NAVY, "ytick.color": SLATE})


def finish(fig, ax, title: str, name: str) -> None:
    ax.set_title(title, fontsize=13, color="#16324F", pad=12)
    ax.grid(axis="y" if ax.get_yscale() == "log" or name != "results" else "x", color="#D9E0E8", linewidth=0.7)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    fig.tight_layout()
    fig.savefig(f"chart_{name}.png", dpi=200, facecolor="white")


# 1. noise to story
fig, ax = plt.subplots(figsize=(6.6, 5.2))
bars = ax.bar(["Packets seen", "Alerts raised", "Incident\nreported"], [2325, 4, 1], color=[STEEL, AMBER, RED], width=0.6)
ax.set_yscale("log"); ax.set_ylim(1, 10000)
for b, v in zip(bars, [2325, 4, 1]):
    ax.text(b.get_x() + b.get_width() / 2, v * 1.25, f"{v:,}", ha="center", fontsize=15, fontweight="bold", color=NAVY)
ax.tick_params(axis="x", labelsize=13)
finish(fig, ax, "Live demo run (log scale)", "noise")

# 2. three clocks
fig, ax = plt.subplots(figsize=(8.0, 5.3))
cats = ["10 seconds", "5 minutes", "1 hour"]
series = [("Alert threshold", [20, 15, 60], AMBER), ("Fast scan: 400 ports in 1 s", [400, 400, 400], RED),
          ("Slow scan: 4 probes a minute", [1, 20, 240], TEAL)]
width = 0.26
for i, (name, vals, color) in enumerate(series):
    xs = [k + (i - 1) * width for k in range(3)]
    bars = ax.bar(xs, vals, width=width * 0.92, color=color, label=name)
    for x, v in zip(xs, vals):
        ax.text(x, v * 1.2, str(v), ha="center", fontsize=12, fontweight="bold", color=NAVY)
ax.set_yscale("log"); ax.set_ylim(1, 1000)
ax.set_xticks(range(3)); ax.set_xticklabels(cats, fontsize=13)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.08), ncol=3, frameon=False, fontsize=10.5)
finish(fig, ax, "Distinct ports probed per window (log scale)", "clocks")

# 3. results
fig, ax = plt.subplots(figsize=(6.4, 5.2))
labels, vals = ["DNS tunnel", "Brute force", "Port scan", "Beaconing"], [1.7, 8.5, 8.9, 12.1]
bars = ax.barh(labels, vals, color=RED, height=0.55)
for b, v in zip(bars, vals):
    ax.text(v + 0.25, b.get_y() + b.get_height() / 2, f"{v:.1f}", va="center", fontsize=14, fontweight="bold", color=NAVY)
ax.set_xlim(0, 15); ax.tick_params(axis="y", labelsize=14)
finish(fig, ax, "Seconds until the alert (reference live run)", "results")
