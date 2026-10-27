"""
Draws slide versions of the GreenBuck result figures for the dark presentation theme.

Reads classification.csv and overhead.csv from results_dir and writes transparent
PNGs sized for a 13.33 x 7.5 in slide to out_dir:
  slide_tradeoff.png  attacker macro-F1, bandwidth overhead and time per action per defense
  slide_ablation.png  macro-F1 per defense from size only, server timing only and all features
  slide_cipher.png    server-timing-only macro-F1 per cipher for no defense, fixed padding and constant-rate

Usage:
  python3 deck_figures.py results_dir out_dir
"""

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

INK, INK_2, MUTED = "#FDFDFD", "#C3C2B7", "#9A9890"
GRID, AXIS = "#3D3F4D", "#5A5C6A"
BRAND = "#EC8717"
SERIES = ["#3987E5", "#D95926", "#199E70"]
DEFENSES = ["none", "padding", "random_padding", "jitter", "constant", "batching"]
DEFENSE_NAMES = {"none": "No defense", "padding": "Fixed padding", "random_padding": "Random padding",
                 "jitter": "Jitter", "constant": "Constant-rate", "batching": "Batching"}
CIPHERS = ["none", "aescbc", "aesgcm", "chacha20"]
CIPHER_NAMES = {"none": "No cipher", "aescbc": "AES-CBC", "aesgcm": "AES-GCM", "chacha20": "ChaCha20"}

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 14, "text.color": INK, "axes.edgecolor": AXIS,
    "axes.linewidth": 1.0, "axes.labelcolor": INK_2, "xtick.color": INK_2, "ytick.color": INK,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
    "axes.facecolor": "none", "figure.facecolor": "none", "savefig.transparent": True,
})


def style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(length=0)


def save(fig, path):
    fig.savefig(path, dpi=220, bbox_inches="tight", transparent=True)
    plt.close(fig)


def tradeoff(cls, ovh, out):
    main = cls[(cls.model == "random_forest") & (cls.features == "all")]
    f1 = main.groupby("mitigation")["macro_f1"].mean()
    cost = ovh.groupby("mitigation")[["bandwidth_overhead_pct", "action_time_added_ms"]].mean()
    chance = main["chance"].iloc[0]
    rows = list(range(len(DEFENSES)))

    fig, axes = plt.subplots(1, 3, figsize=(11.6, 3.7), sharey=True,
                             gridspec_kw={"width_ratios": [1.1, 1, 1]})
    ax = axes[0]
    style(ax)
    for y, d in zip(rows, DEFENSES):
        ax.hlines(y, 0, f1[d], color=GRID, linewidth=1.0, zorder=1)
        ax.scatter(f1[d], y, s=110, color=BRAND, edgecolor="#252733", linewidth=2, zorder=3)
        ax.text(f1[d] - 0.05, y, f"{f1[d]:.2f}", ha="right", va="center", fontsize=13, color=INK)
    ax.axvline(chance, color=MUTED, linewidth=1.2, zorder=2)
    ax.text(chance + 0.02, len(DEFENSES) - 0.45, "chance", color=MUTED, fontsize=12)
    ax.set_xlim(0, 1.08)
    ax.set_xticks([0, 0.5, 1.0])
    ax.set_title("Attacker accuracy (macro-F1)", fontsize=14, color=INK, loc="left", pad=10)
    ax.set_yticks(rows, [DEFENSE_NAMES[d] for d in DEFENSES])
    ax.invert_yaxis()

    # Values inside the noise band print as "≈0": 1% of bandwidth, 30 ms of action time.
    panels = [(axes[1], "bandwidth_overhead_pct", "Bandwidth cost", "{:+.0f}%", 20, 1, "0%"),
              (axes[2], "action_time_added_ms", "Time cost per action", "{:+.0f} ms", 45, 30, "≈0 ms")]
    for ax, column, title, label, pad, noise, zero in panels:
        style(ax)
        values = [cost.loc[d, column] for d in DEFENSES]
        ax.barh(rows, values, height=0.55, color=BRAND, zorder=2)
        for y, v in zip(rows[1:], values[1:]):
            text = label.format(v) if abs(v) >= noise else zero
            ax.text(max(v, 0) + pad, y, text, va="center", fontsize=13, color=INK)
        ax.axvline(0, color=AXIS, linewidth=1.0, zorder=1)
        ax.set_xlim(min(min(values), 0) - 2 * pad, max(values) * 1.38)
        ax.set_title(title, fontsize=14, color=INK, loc="left", pad=10)
        ax.set_xticks([])
    for ax in axes:
        ax.grid(axis="y", visible=False)
    fig.tight_layout(w_pad=1.5)
    save(fig, out / "slide_tradeoff.png")


def ablation(cls, out):
    rf = cls[cls.model == "random_forest"]
    means = rf.groupby(["mitigation", "features"])["macro_f1"].mean().unstack()
    chance = rf["chance"].iloc[0]
    sets = [("size", "Size only"), ("server_timing", "Server timing only"), ("all", "All features")]

    fig, ax = plt.subplots(figsize=(11.6, 3.6))
    style(ax)
    width, gap = 0.25, 0.03
    for i, (key, name) in enumerate(sets):
        xs = [k + (i - 1) * (width + gap) for k in range(len(DEFENSES))]
        ax.bar(xs, [means.loc[d, key] for d in DEFENSES], width=width, color=SERIES[i], label=name, zorder=2)
    ax.set_xticks(range(len(DEFENSES)), [DEFENSE_NAMES[d].replace(" ", "\n", 1) for d in DEFENSES])
    ax.tick_params(axis="x", colors=INK)
    ax.set_ylim(0, 1.05)
    ax.set_yticks([0, 0.5, 1.0])
    ax.set_xlim(-0.5, len(DEFENSES) - 0.5 + 0.6)
    ax.set_ylabel("Attacker macro-F1")
    ax.grid(axis="x", visible=False)
    ax.axhline(chance, color=MUTED, linewidth=1.2, zorder=1)
    ax.text(len(DEFENSES) - 0.5 + 0.08, chance + 0.03, "chance", color=MUTED, fontsize=12)
    ax.legend(frameon=False, ncol=3, loc="lower left", bbox_to_anchor=(0, 1.0), fontsize=13,
              labelcolor=INK)
    fig.tight_layout()
    save(fig, out / "slide_ablation.png")


def cipher(cls, out):
    st = cls[(cls.model == "random_forest") & (cls.features == "server_timing")].set_index(
        ["mitigation", "encryption"])
    chance = cls["chance"].iloc[0]
    shown = ["none", "padding", "constant"]
    styles = {"none": (MUTED, "o"), "aescbc": (SERIES[0], "s"), "aesgcm": (SERIES[1], "D"),
              "chacha20": (SERIES[2], "^")}

    fig, ax = plt.subplots(figsize=(11.6, 3.5))
    style(ax)
    for row, d in enumerate(shown):
        for k, c in enumerate(CIPHERS):
            y = row + (k - 1.5) * 0.18
            r = st.loc[(d, c)]
            color, marker = styles[c]
            ax.hlines(y, r.macro_f1_low, r.macro_f1_high, color=color, linewidth=2.2, zorder=2)
            ax.scatter(r.macro_f1, y, s=90, color=color, marker=marker, edgecolor="#252733",
                       linewidth=1.5, zorder=3, label=CIPHER_NAMES[c] if row == 0 else None)
    ax.set_yticks(range(len(shown)), [DEFENSE_NAMES[d] for d in shown])
    ax.invert_yaxis()
    ax.set_xlim(0, 0.8)
    ax.set_xticks([0, 0.2, 0.4, 0.6, 0.8])
    ax.grid(axis="y", visible=False)
    ax.axvline(chance, color=MUTED, linewidth=1.2, zorder=1)
    ax.text(chance + 0.008, -0.42, "chance", color=MUTED, fontsize=12, va="top")
    ax.set_xlabel("Attacker macro-F1 from server timing alone (95% interval)")
    ax.legend(frameon=False, ncol=4, loc="lower left", bbox_to_anchor=(0, 1.0), fontsize=13,
              labelcolor=INK)
    fig.tight_layout()
    save(fig, out / "slide_cipher.png")


def main():
    parser = argparse.ArgumentParser(description="Draw slide figures for the dark deck theme.")
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    cls = pd.read_csv(args.results_dir / "classification.csv")
    ovh = pd.read_csv(args.results_dir / "overhead.csv")
    tradeoff(cls, ovh, args.out_dir)
    ablation(cls, args.out_dir)
    cipher(cls, args.out_dir)
    print(f"wrote slide figures to {args.out_dir}")


if __name__ == "__main__":
    main()
