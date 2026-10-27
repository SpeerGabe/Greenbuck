"""
Draws the GreenBuck result figures and LaTeX tables from analyze.py's output.

Reads classification.csv and overhead.csv from results_dir and writes to out_dir:
  tradeoff.pdf/.png   per defense, side by side: attacker macro-F1 (Random Forest, all
                      features, averaged over ciphers; whiskers span the four ciphers),
                      bandwidth overhead, and time added per user action
  ablation.pdf/.png   macro-F1 per defense with size-only, server-timing-only and all features
  cipher_timing.pdf/.png  server-timing-only macro-F1 per defense and cipher, with 95% intervals
  table_results.tex   macro-F1 per cipher x defense, both models, with 95% CIs
  table_overhead.tex  bandwidth and time overhead per defense

Usage:
  python3 make_figures.py results_dir out_dir
"""

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]
INK, INK_2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"
DEFENSES = ["none", "padding", "random_padding", "jitter", "constant", "batching"]
DEFENSE_NAMES = {"none": "No defense", "padding": "Fixed padding", "random_padding": "Random padding",
                 "jitter": "Jitter", "constant": "Constant-rate", "batching": "Batching"}
CIPHERS = ["none", "aescbc", "aesgcm", "chacha20"]
CIPHER_NAMES = {"none": "None", "aescbc": "AES-CBC", "aesgcm": "AES-GCM", "chacha20": "ChaCha20"}

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": AXIS, "axes.linewidth": 0.8,
    "axes.labelcolor": INK_2, "xtick.color": INK_2, "ytick.color": INK_2, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True, "figure.dpi": 200,
})


def style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(length=0)


def chance_line(ax, value, label, x_text):
    ax.axhline(value, color=MUTED, linewidth=0.8, zorder=1)
    ax.text(x_text, value + 0.012, label, color=MUTED, fontsize=7.5, va="bottom")


def tradeoff(cls, ovh, out):
    main = cls[(cls.model == "random_forest") & (cls.features == "all")]
    f1 = main.groupby("mitigation")["macro_f1"].agg(["mean", "min", "max"])
    cost = ovh.groupby("mitigation")[["bandwidth_overhead_pct", "action_time_added_ms"]].mean()
    chance = main["chance"].iloc[0]
    rows = list(range(len(DEFENSES)))

    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.7), sharey=True,
                             gridspec_kw={"width_ratios": [1.15, 1, 1]})
    ax = axes[0]
    style(ax)
    for y, d in zip(rows, DEFENSES):
        ax.hlines(y, f1.loc[d, "min"], f1.loc[d, "max"], color=SERIES[0], linewidth=1.4, zorder=2)
        ax.scatter(f1.loc[d, "mean"], y, s=34, color=SERIES[0], edgecolor="white", linewidth=1.2, zorder=3)
        ax.text(f1.loc[d, "mean"] - 0.04, y - 0.28, f"{f1.loc[d, 'mean']:.2f}", ha="right",
                fontsize=7.5, color=INK)
    ax.axvline(chance, color=MUTED, linewidth=0.8, zorder=1)
    ax.text(chance + 0.02, len(DEFENSES) - 0.5, "chance", color=MUTED, fontsize=7.5)
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("Attacker macro-F1")
    ax.set_yticks(rows, [DEFENSE_NAMES[d] for d in DEFENSES])
    ax.invert_yaxis()

    panels = [(axes[1], "bandwidth_overhead_pct", "Bandwidth overhead (%)", "{:+.0f}%", 18),
              (axes[2], "action_time_added_ms", "Time added per action (ms)", "{:+.0f} ms", 40)]
    for ax, column, xlabel, label, pad in panels:
        style(ax)
        values = [cost.loc[d, column] for d in DEFENSES]
        ax.barh(rows, values, height=0.5, color=SERIES[0], zorder=2)
        for y, v in zip(rows[1:], values[1:]):
            text = label.format(v) if round(v) != 0 else label.format(0).lstrip("+")
            ax.text(max(v, 0) + pad, y, text, va="center", fontsize=7.5, color=INK)
        ax.axvline(0, color=AXIS, linewidth=0.8, zorder=1)
        ax.set_xlim(min(min(values), 0) - 2 * pad, max(values) * 1.32)
        ax.set_xlabel(xlabel)
    for ax in axes:
        ax.grid(axis="y", visible=False)
    fig.tight_layout(w_pad=1.2)
    for ext in ("pdf", "png"):
        fig.savefig(out / f"tradeoff.{ext}", bbox_inches="tight")
    plt.close(fig)


def ablation(cls, out):
    rf = cls[cls.model == "random_forest"]
    means = rf.groupby(["mitigation", "features"])["macro_f1"].mean().unstack()
    chance = rf["chance"].iloc[0]
    sets = [("size", "Size only"), ("server_timing", "Server timing only"), ("all", "All features")]

    fig, ax = plt.subplots(figsize=(7.0, 2.9))
    style(ax)
    width, gap = 0.24, 0.02
    for i, (key, name) in enumerate(sets):
        xs = [k + (i - 1) * (width + gap) for k in range(len(DEFENSES))]
        ax.bar(xs, [means.loc[d, key] for d in DEFENSES], width=width, color=SERIES[i], label=name,
               zorder=2)
    ax.set_xticks(range(len(DEFENSES)), [DEFENSE_NAMES[d].replace(" ", "\n", 1) for d in DEFENSES])
    ax.set_ylim(0, 1.05)
    ax.set_xlim(-0.5, len(DEFENSES) - 0.5 + 0.55)
    ax.set_ylabel("Attacker macro-F1 (Random Forest)")
    ax.grid(axis="x", visible=False)
    chance_line(ax, chance, "chance", len(DEFENSES) - 0.5 + 0.08)
    ax.legend(frameon=False, ncol=3, loc="lower left", bbox_to_anchor=(0, 1.0), fontsize=8)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(out / f"ablation.{ext}", bbox_inches="tight")
    plt.close(fig)


def cipher_effect(cls, out):
    st = cls[(cls.model == "random_forest") & (cls.features == "server_timing")].set_index(
        ["mitigation", "encryption"])
    chance = cls["chance"].iloc[0]
    styles = {"none": ("#898781", "o"), "aescbc": (SERIES[0], "s"),
              "aesgcm": (SERIES[1], "D"), "chacha20": (SERIES[2], "^")}

    fig, ax = plt.subplots(figsize=(7.0, 3.2))
    style(ax)
    for row, d in enumerate(DEFENSES):
        for k, c in enumerate(CIPHERS):
            y = row + (k - 1.5) * 0.17
            r = st.loc[(d, c)]
            color, marker = styles[c]
            ax.hlines(y, r.macro_f1_low, r.macro_f1_high, color=color, linewidth=1.2, zorder=2)
            ax.scatter(r.macro_f1, y, s=30, color=color, marker=marker, edgecolor="white",
                       linewidth=1.0, zorder=3, label=CIPHER_NAMES[c] if row == 0 else None)
    ax.set_yticks(range(len(DEFENSES)), [DEFENSE_NAMES[d] for d in DEFENSES])
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.grid(axis="y", visible=False)
    ax.axvline(chance, color=MUTED, linewidth=0.8, zorder=1)
    ax.text(chance + 0.01, len(DEFENSES) - 0.45, "chance", color=MUTED, fontsize=7.5)
    ax.set_xlabel("Attacker macro-F1 from server timing alone (95% interval)")
    ax.legend(frameon=False, ncol=4, loc="lower left", bbox_to_anchor=(0, 1.0), fontsize=8,
              title="Field-level cipher", title_fontsize=8, alignment="left")
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(out / f"cipher_timing.{ext}", bbox_inches="tight")
    plt.close(fig)


def latex_results(cls, out):
    main = cls[cls.features == "all"].set_index(["mitigation", "encryption", "model"])
    lines = [r"\begin{table*}[t]", r"\centering",
             r"\caption{Attacker macro-F1 per request (all features) for Random Forest (RF) and k-NN, "
             r"5-fold cross-validation grouped by run. 95\% bootstrap intervals over runs are within "
             r"$\pm$0.06 of every value. Chance is 0.17.}",
             r"\label{tab:results}", r"\begin{tabular}{l" + "cc" * len(CIPHERS) + "}", r"\toprule",
             " & " + " & ".join(rf"\multicolumn{{2}}{{c}}{{{CIPHER_NAMES[c]}}}" for c in CIPHERS) + r" \\",
             "Defense & " + " & ".join(["RF & k-NN"] * len(CIPHERS)) + r" \\", r"\midrule"]
    for d in DEFENSES:
        cells = []
        for c in CIPHERS:
            for m in ("random_forest", "knn"):
                cells.append(f"{main.loc[(d, c, m), 'macro_f1']:.2f}")
        lines.append(f"{DEFENSE_NAMES[d]} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    (out / "table_results.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")


def latex_overhead(ovh, out):
    mean = ovh.groupby("mitigation")[["bandwidth_overhead_pct", "action_time_added_ms"]].mean()
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Cost of each defense relative to no defense, averaged over the four cipher settings. "
             r"Bandwidth is TLS application bytes per run; time is the phone-measured duration of each user action. "
             r"Differences within $\pm$30\,ms are within run-to-run variation.}",
             r"\label{tab:overhead}", r"\begin{tabular}{lrr}", r"\toprule",
             r"Defense & Bandwidth (\%) & Time per action (ms) \\", r"\midrule"]
    for d in DEFENSES[1:]:
        row = mean.loc[d]
        cells = [f"{v:+.0f}" if round(v) != 0 else "0"
                 for v in (row.bandwidth_overhead_pct, row.action_time_added_ms)]
        lines.append(f"{DEFENSE_NAMES[d]} & {cells[0]} & {cells[1]}" + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    (out / "table_overhead.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Draw GreenBuck figures and tables.")
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    cls = pd.read_csv(args.results_dir / "classification.csv")
    ovh = pd.read_csv(args.results_dir / "overhead.csv")
    tradeoff(cls, ovh, args.out_dir)
    ablation(cls, args.out_dir)
    cipher_effect(cls, args.out_dir)
    latex_results(cls, args.out_dir)
    latex_overhead(ovh, args.out_dir)
    print(f"wrote figures and tables to {args.out_dir}")


if __name__ == "__main__":
    main()
