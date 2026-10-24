# research-server-incident-resilience

Analysis of a synthetic ransomware-style incident on a university research server, with a resilient
security architecture, a recovery plan checked against RPO ≤ 5 min and RTO ≤ 30 min, and an
AI-assisted detection calculation. Coursework for Fault Tolerance and Reliability (Astana IT
University, Assignment 4, Security, Resilience, and Intrusion Tolerance).

Author: Serikbekov Nurzhan (student ID 255149, group CSE-2505M).

All data are synthetic and educational. They do not describe real AITU infrastructure or any real
incident.

## Layout

| Path | Content |
|---|---|
| `data/incident.json` | the event log and the anomaly scores given in the assignment |
| `data/assessment.json` | my decisions: attack stage per event, likelihood and impact per threat, controls, recovery steps and timing, recommendation |
| `analysis/analyze.py` | computes risk scores and ranks, the recovery critical path (RTO), the worst-case data-loss window (RPO) and the anomaly statistics; fails if a target is missed |
| `results/analysis.json` | output of `analyze.py`, committed |
| `docs/diagram.py`, `docs/architecture.png` | the architecture diagram and its generator |

## Run

```
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt
python analysis/analyze.py
python docs/diagram.py
```

## Method

- Risk = likelihood × impact on 1-5 scales; levels 1-4 Low, 5-9 Medium, 10-16 High, 17-25 Critical.
  Ties are ranked by impact. Residual risk is scored the same way for the target architecture.
- RTO is the end of the critical path of the seven recovery steps (evidence preservation runs in
  parallel with backup activation); dependencies are checked.
- RPO worst case = snapshot interval + shipping lag + detection time + isolation time.
- The restore time of the hot dataset is estimated from an assumed size and throughput.
  Timings and sizes are design budgets, not measurements: nothing here was run against real
  infrastructure.
