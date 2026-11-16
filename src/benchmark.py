import time

import numpy as np

from src.stream import load_stream
from src.scoring import IntrusionScorer


def main():
    flows = load_stream().drop(columns=["family", "label"]).head(5000).to_dict("records")
    scorer = IntrusionScorer()
    for flow in flows[:50]:  # échauffement
        scorer.score(flow)

    latencies = []
    for flow in flows[:1000]:
        t0 = time.perf_counter()
        scorer.score(flow)
        latencies.append((time.perf_counter() - t0) * 1000)
    print(f"un flux à la fois : p50 {np.percentile(latencies, 50):.2f} ms, p95 {np.percentile(latencies, 95):.2f} ms, "
          f"{1000 / np.mean(latencies):.0f} flux/s")

    start = time.perf_counter()
    for i in range(0, len(flows), 500):
        scorer.score_many(flows[i:i + 500])
    print(f"par lots de 500 : {len(flows) / (time.perf_counter() - start):.0f} flux/s")


if __name__ == "__main__":
    main()
