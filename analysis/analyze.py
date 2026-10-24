"""Computes the numbers of the report from data/*.json and writes results/analysis.json."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "analysis.json"
DEPENDS_ON = {1: [], 2: [1], 3: [2], 4: [2], 5: [4], 6: [5], 7: [6, 3]}


def level(score: int) -> str:
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def risks(threats: list[dict]) -> dict:
    rows = []
    for t in threats:
        r = t["residual"]
        rows.append(
            {
                "threat": t["threat"],
                "likelihood": t["likelihood"],
                "impact": t["impact"],
                "score": t["likelihood"] * t["impact"],
                "level": level(t["likelihood"] * t["impact"]),
                "residual_likelihood": r["likelihood"],
                "residual_impact": r["impact"],
                "residual_score": r["likelihood"] * r["impact"],
                "residual_level": level(r["likelihood"] * r["impact"]),
            }
        )
    ranked = sorted(rows, key=lambda x: (-x["score"], -x["impact"]))
    for rank, row in enumerate(ranked, start=1):
        row["priority"] = rank
    total, residual = sum(r["score"] for r in rows), sum(r["residual_score"] for r in rows)
    return {
        "rows": rows,
        "ties": sorted(
            {r["score"] for r in rows if sum(x["score"] == r["score"] for x in rows) > 1}
        ),
        "total": total,
        "residual_total": residual,
        "reduction_pct": round(100 * (total - residual) / total, 1),
    }


def recovery(plan: dict) -> dict:
    steps, p = plan["steps"], plan["parameters"]
    end = {s["step"]: s["start_s"] + s["duration_s"] for s in steps}
    start = {s["step"]: s["start_s"] for s in steps}
    for step, deps in DEPENDS_ON.items():
        for d in deps:
            assert start[step] >= end[d], f"step {step} starts before step {d} ends"
    rto = max(end.values())
    assert rto <= p["rto_target_s"], f"RTO {rto}s exceeds {p['rto_target_s']}s"

    detect, isolate = steps[0]["duration_s"], steps[1]["duration_s"]

    def loss(interval_s: int) -> int:
        return interval_s + p["ship_lag_s"] + detect + isolate

    rpo = loss(p["snapshot_interval_s"])
    assert rpo <= p["rpo_target_s"], f"RPO {rpo}s exceeds {p['rpo_target_s']}s"
    restore_s = p["hot_set_gb"] / p["restore_throughput_gb_s"]
    assert restore_s <= steps[4]["duration_s"], "hot set does not restore inside step 5"
    return {
        "steps": [{**s, "end_s": end[s["step"]]} for s in steps],
        "rto_s": rto,
        "rto_target_s": p["rto_target_s"],
        "rto_margin_s": p["rto_target_s"] - rto,
        "rpo_worst_case_s": rpo,
        "rpo_target_s": p["rpo_target_s"],
        "rpo_margin_s": p["rpo_target_s"] - rpo,
        "rpo_by_snapshot_interval_s": {str(i): loss(i) for i in (30, 60, 120, 300)},
        "restore_hot_set_s": round(restore_s),
        "restore_budget_s": steps[4]["duration_s"],
        "isolation_done_s": end[2],
        "parameters": p,
    }


def anomalies(scores: list[dict], threshold: float) -> dict:
    rows = []
    for s in scores:
        rows.append(
            {
                **s,
                "delta": round(s["observed"] - s["normal"], 2),
                "ratio": round(s["observed"] / s["normal"], 2),
                "margin": round(s["observed"] - threshold, 2),
                "anomaly": s["observed"] >= threshold,
            }
        )
    flagged = [r for r in rows if r["anomaly"]]
    ranked = sorted(rows, key=lambda r: -r["observed"])
    sensitivity = {}
    for t in (0.70, 0.75, 0.80, 0.85, 0.90, 0.95):
        n = sum(r["observed"] >= t for r in rows)
        sensitivity[f"{t:.2f}"] = {"detected": n, "rate_pct": round(100 * n / len(rows))}
    return {
        "rows": rows,
        "threshold": threshold,
        "detected": len(flagged),
        "total": len(rows),
        "rate_pct": round(100 * len(flagged) / len(rows), 1),
        "normal_flagged": sum(r["normal"] >= threshold for r in rows),
        "mean_normal": round(sum(r["normal"] for r in rows) / len(rows), 3),
        "mean_observed": round(sum(r["observed"] for r in rows) / len(rows), 3),
        "highest": ranked[0]["signal"],
        "ranking": [r["signal"] for r in ranked],
        "sensitivity": sensitivity,
    }


def main() -> None:
    incident = json.loads((ROOT / "data" / "incident.json").read_text(encoding="utf-8"))
    assessment = json.loads((ROOT / "data" / "assessment.json").read_text(encoding="utf-8"))
    events = {e["time"] for e in incident["events"]}
    assert events == set(assessment["stages"]) == {c["time"] for c in assessment["coverage"]}

    result = {
        "stages": {
            "counts": {
                stage: sum(v["stage"] == stage for v in assessment["stages"].values())
                for stage in sorted({v["stage"] for v in assessment["stages"].values()})
            },
            "raised": [
                t for t, v in assessment["stages"].items()
                if v["risk"] != next(e["severity"] for e in incident["events"] if e["time"] == t)
            ],
        },
        "risk": risks(assessment["threats"]),
        "recovery": recovery(assessment["recovery"]),
        "anomalies": anomalies(incident["scores"], incident["anomaly_threshold"]),
    }  # fmt: skip
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    r, a = result["recovery"], result["anomalies"]
    print(
        f"RTO {r['rto_s'] / 60:.0f} min (target {r['rto_target_s'] / 60:.0f}), "
        f"RPO worst case {r['rpo_worst_case_s']} s (target {r['rpo_target_s']}), "
        f"anomalies {a['detected']}/{a['total']}, risk {result['risk']['total']} -> "
        f"{result['risk']['residual_total']}"
    )


if __name__ == "__main__":
    main()
