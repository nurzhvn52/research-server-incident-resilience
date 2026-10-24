"""Draws docs/architecture.png (the resilient security architecture)."""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).resolve().parent / "architecture.png"
INK, MUTED, FILL, ZONE = "#0b0b0b", "#52514e", "#ffffff", "#f3f2ee"


def zone(ax, x, y, w, h, title):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.15",
                                fc=ZONE, ec="none"))  # fmt: skip
    ax.text(x + 0.2, y + h - 0.15, title, fontsize=8, color=MUTED, va="top")


def box(ax, x, y, w, h, title, lines=(), dashed=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=FILL, ec=MUTED, lw=1.1, ls="--" if dashed else "-"))  # fmt: skip
    ax.text(x + w / 2, y + h - 0.17, title, ha="center", va="top", fontsize=9, color=INK,
            weight="bold")  # fmt: skip
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.5 - i * 0.26, line, ha="center", va="top", fontsize=7.5,
                color=MUTED)  # fmt: skip


def arrow(ax, a, b, label="", dashed=False, side="above"):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=11, color=INK, lw=1.1,
                                 ls="--" if dashed else "-"))  # fmt: skip
    if label:
        mx, my = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2
        if a[1] == b[1]:
            ax.text(mx, my + 0.16, label, fontsize=7.5, color=INK, ha="center", va="bottom")
        else:
            ax.text(mx + 0.12, my, label, fontsize=7.5, color=INK, ha="left", va="center")


def main() -> None:
    fig, ax = plt.subplots(figsize=(12, 8.6))
    ax.set_xlim(0, 16.8)
    ax.set_ylim(0, 11)
    ax.axis("off")

    box(
        ax,
        0.9,
        9.15,
        3.5,
        1.3,
        "Researchers",
        ["lab and office VLANs", "no direct path to servers"],
    )
    box(
        ax,
        5.1,
        9.15,
        3.5,
        1.3,
        "Identity provider",
        ["MFA (FIDO2 / TOTP)", "lockout after 5 failures"],
    )
    box(ax, 9.3, 9.15, 3.5, 1.3, "Bastion / access proxy", ["only entry to SSH and RDP",
                                                          "just-in-time admin rights"])  # fmt: skip
    ax.text(14.35, 9.8, "Zero Trust:\nevery request is\nverified, no trust\nby network position",
            ha="center", va="center", fontsize=8, color=MUTED, style="italic")  # fmt: skip
    arrow(ax, (4.4, 9.8), (5.1, 9.8), "1")
    arrow(ax, (8.6, 9.8), (9.3, 9.8), "2")

    ax.add_patch(FancyBboxPatch((0.9, 7.75), 14.9, 0.75, boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=FILL, ec=INK, lw=1.4))  # fmt: skip
    ax.text(8.35, 8.125, "Segmentation firewall: default deny between zones, default-deny outbound, "
            "quarantine VLAN", ha="center", va="center", fontsize=9, weight="bold",
            color=INK)  # fmt: skip
    arrow(ax, (11.05, 9.15), (11.05, 8.5), "3")

    zone(ax, 0.9, 3.75, 4.6, 3.6, "Research segment 10.20.10.0/24")
    box(ax, 1.2, 5.15, 4.0, 1.6, "Research-Server-01", ["EDR with tamper protection",
                                                        "file-integrity monitor + canary files",
                                                        "no delete rights on backups"])  # fmt: skip
    box(ax, 1.2, 3.95, 4.0, 0.95, "Database", ["service account, query-rate limit"])
    arrow(ax, (3.2, 7.75), (3.2, 7.35))

    zone(ax, 6.2, 3.75, 4.6, 3.6, "Backup segment 10.20.50.0/24")
    box(ax, 6.5, 5.15, 4.0, 1.6, "Immutable repository", ["object lock, 14-day retention",
                                                          "pulls snapshots, own credentials",
                                                          "retention change needs 2 approvers"])  # fmt: skip
    box(ax, 6.5, 3.95, 4.0, 0.95, "Offline copy, second site", ["air-gapped, daily"], dashed=True)
    arrow(ax, (8.5, 5.15), (8.5, 4.9))
    arrow(ax, (5.2, 5.95), (6.5, 5.95), "4 pull, 60 s")

    zone(ax, 11.5, 3.75, 4.3, 3.6, "Recovery environment 10.20.90.0/24")
    box(ax, 11.8, 5.15, 3.7, 1.6, "Research-Server-02", ["clean-room standby, no user route",
                                                         "malware scan before promotion",
                                                         "promoted only by the controller"])  # fmt: skip
    box(ax, 11.8, 3.95, 3.7, 0.95, "Failover controller", ["verify, authenticate, validate"])
    arrow(ax, (10.5, 5.95), (11.8, 5.95), "5 restore")
    arrow(ax, (15.1, 7.35), (15.1, 7.75), "6")

    zone(ax, 0.9, 0.3, 14.9, 2.35, "Monitoring plane 10.20.60.0/24")
    parts = [
        ("SIEM", ["log correlation", "brute-force rules"]),
        ("NIDS + NetFlow", ["new destinations", "traffic volume"]),
        ("AI anomaly scorer", ["alert at score >= 0.75", "complements the rules"]),
        ("SOAR playbook", ["isolate, revoke sessions", "block destination"]),
    ]
    for i, (title, lines) in enumerate(parts):
        box(ax, 1.2 + i * 3.7, 0.5, 3.3, 1.4, title, lines)
    for x in (3.2, 8.5, 13.65):
        arrow(ax, (x, 3.75), (x, 2.65), dashed=True)
    ax.text(8.7, 3.2, "7  logs, EDR and canary alerts, NetFlow", fontsize=7.5, color=INK,
            ha="left", va="center")  # fmt: skip

    ax.plot([15.5, 16.3, 16.3], [1.2, 1.2, 8.125], color=INK, lw=1.1, ls="--")
    arrow(ax, (16.3, 8.125), (15.8, 8.125))
    ax.text(16.55, 4.7, "8  isolate / block", fontsize=7.5, color=INK, rotation=90, ha="center",
            va="center")  # fmt: skip

    fig.savefig(OUT, dpi=200, bbox_inches="tight", facecolor="white")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
