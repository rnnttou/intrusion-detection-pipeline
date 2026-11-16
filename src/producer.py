import argparse
import json
import os
import time

from confluent_kafka import Producer

from src.stream import load_stream

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:19093")


def main():
    ap = argparse.ArgumentParser(description="Rejoue les flux réseau du jeu de test sur Redpanda")
    ap.add_argument("--rate", type=float, default=200, help="flux par seconde")
    ap.add_argument("--limit", type=int, default=None, help="nombre max de flux")
    ap.add_argument("--attack-share", type=float, default=None, help="part d'attaques dans le rejeu (ex. 0.05)")
    args = ap.parse_args()

    stream = load_stream(attack_share=args.attack_share)
    if args.limit:
        stream = stream.head(args.limit)

    producer = Producer({"bootstrap.servers": BOOTSTRAP})
    start = time.perf_counter()
    for i, row in enumerate(stream.to_dict("records")):
        producer.produce("flows", json.dumps(row).encode())
        producer.poll(0)
        # le i-ème flux part à start + i / rate : on dort seulement le temps restant
        delay = start + (i + 1) / args.rate - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
    producer.flush()
    print(f"{len(stream)} flux envoyés en {time.perf_counter() - start:.1f} s")


if __name__ == "__main__":
    main()
