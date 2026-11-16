import argparse
import json
import os
import time

from confluent_kafka import Consumer, Producer

from src import db
from src.features import PORT
from src.scoring import IntrusionScorer

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:19093")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--idle-exit", type=float, default=None,
                    help="s'arrête proprement après N secondes sans message (utile pour les tests)")
    ap.add_argument("--batch-size", type=int, default=500, help="taille max d'un lot")
    ap.add_argument("--max-wait", type=float, default=0.2,
                    help="attente max en secondes pour remplir un lot : borne le retard d'une alerte")
    args = ap.parse_args()

    scorer = IntrusionScorer()
    conn = db.get_conn()
    db.init_db(conn)

    # enable.auto.commit=False : l'offset n'avance qu'après l'écriture du lot dans Postgres.
    # Si le consumer plante, le lot en cours est relu (au moins une fois, doublons possibles).
    consumer = Consumer({"bootstrap.servers": BOOTSTRAP, "group.id": "ids-scorer",
                         "auto.offset.reset": "earliest", "enable.auto.commit": False})
    consumer.subscribe(["flows"])
    alerts = Producer({"bootstrap.servers": BOOTSTRAP})

    count, first_msg, last_msg, last_write = 0, None, time.monotonic(), None
    try:
        while True:
            # un lot = ce qui arrive en max_wait secondes, plafonné à batch_size
            msgs = [m for m in consumer.consume(args.batch_size, timeout=args.max_wait) if not m.error()]
            if not msgs:
                if args.idle_exit and count and time.monotonic() - last_msg > args.idle_exit:
                    break
                continue
            last_msg = time.monotonic()
            first_msg = first_msg or last_msg
            flows = [json.loads(m.value()) for m in msgs]
            # les vraies étiquettes ne servent qu'au suivi, jamais au score
            truth = [(f.pop("family", None), f.pop("label", None)) for f in flows]
            results = scorer.score_many(flows)
            for flow, result in zip(flows, results):
                if result["is_alert"]:
                    alert = {"dst_port": flow.get(PORT), **result}
                    alerts.produce("intrusion-alerts", json.dumps(alert).encode())
            alerts.poll(0)
            db.save_detections(conn, [(flow.get(PORT), result, family, label)
                                      for flow, result, (family, label) in zip(flows, results, truth)])
            consumer.commit(asynchronous=False)
            last_write = time.monotonic()
            count += len(msgs)
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()  # sans close(), le prochain démarrage attend ~45 s
        alerts.flush()
        conn.close()
        print(f"{count} flux traités")
        if count > 1 and last_write:
            elapsed = last_write - first_msg
            print(f"débit de bout en bout : {count / elapsed:.0f} flux/s ({elapsed:.1f} s)")


if __name__ == "__main__":
    main()
