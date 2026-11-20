"""Run a complete experiment with synthetic readings and PostgreSQL."""

import argparse
from contextlib import ExitStack
from fractions import Fraction
import gc
import json
import os
from pathlib import Path
import random
from time import perf_counter, process_time
from uuid import UUID, uuid4

import psutil
import psycopg
import tenseal as ts

from crypto import MAX_ROWS, create_contexts, decrypt_results, encrypt_reading, evaluate

DSN = "postgresql://city:local_demo@localhost:5432/smart_city"
KEYS = Path(__file__).resolve().parent / "keys"
SENSORS = {
    "traffic": (0, 100, "vehicles/min"),
    "air_quality": (10, 100, "AQI"),
    "parking": (0, 100, "%"),
    "street_light": (0, 100, "% output"),
    "temperature": (16, 42, "deg C"),
}
CREATE_ENCRYPTED = """
CREATE TABLE IF NOT EXISTS encrypted_readings (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id uuid NOT NULL,
    sensor text NOT NULL,
    payload bytea NOT NULL
)
"""


def store_readings(db, run_id, public, samples):
    db.execute(CREATE_ENCRYPTED)
    db.execute("CREATE INDEX IF NOT EXISTS encrypted_run_sensor "
               "ON encrypted_readings (run_id, sensor)")
    with db.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO encrypted_readings (run_id, sensor, payload) VALUES (%s, %s, %s)",
            ((run_id, sensor, encrypt_reading(public, value))
             for sensor, readings in samples.items() for value in readings),
        )


def store_plaintext_baseline(db, samples):
    db.execute("CREATE TEMP TABLE benchmark_readings (sensor text, reading integer)")
    with db.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO benchmark_readings (sensor, reading) VALUES (%s, %s)",
            ((sensor, value) for sensor, readings in samples.items() for value in readings),
        )
    db.execute("CREATE INDEX ON benchmark_readings (sensor)")


def fetch_encrypted(db, run_id, sensor):
    rows = db.execute(
        "SELECT payload FROM encrypted_readings WHERE run_id = %s AND sensor = %s",
        (run_id, sensor),
    )
    return [row[0] for row in rows]


def plaintext_query(db, sensor):
    total, average, smallest, largest = db.execute(
        "SELECT SUM(reading), AVG(reading), MIN(reading), MAX(reading) "
        "FROM benchmark_readings WHERE sensor = %s", (sensor,),
    ).fetchone()
    return total, average, smallest, largest


def encrypted_query(db, run_id, sensor, public):
    rows = fetch_encrypted(db, run_id, sensor)
    return (*evaluate(public, rows), len(rows))


def rss_bytes():
    # Sample live resident memory, including TenSEAL's native allocations.
    return psutil.Process().memory_info().rss


def measure(query, repeats):
    gc.collect()
    initial_rss = rss_bytes()
    wall = cpu = 0.0
    largest_rss = initial_rss
    for _ in range(repeats):
        start_wall, start_cpu = perf_counter(), process_time()
        result = query()
        cpu += process_time() - start_cpu
        wall += perf_counter() - start_wall
        largest_rss = max(largest_rss, rss_bytes())
    return result, {
        "mean_wall_ms": round(wall * 1000 / repeats, 4),
        "mean_python_process_cpu_ms": round(cpu * 1000 / repeats, 4),
        "before_rss_bytes": initial_rss,
        "max_post_query_rss_bytes": largest_rss,
    }


def verify_public_context(public, payload):
    if public.has_secret_key():
        raise RuntimeError("Unexpected secret key in evaluator")
    try:
        ts.bfv_vector_from(public, payload).decrypt()
    except (ValueError, RuntimeError):
        return
    raise RuntimeError("Evaluator decrypted a database record")


def run(dsn, count, repeats, benchmark):
    rng = random.SystemRandom()
    samples = {
        sensor: [rng.randint(low, high) for _ in range(count)]
        for sensor, (low, high, _) in SENSORS.items()
    }
    run_id = uuid4()
    owner, public = create_contexts()
    report = {"run_id": str(run_id), "rows_per_sensor": count, "repeats": repeats,
              "sensors": {}}

    KEYS.mkdir(mode=0o700, exist_ok=True)
    key_path = KEYS / f"{run_id}.seal"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    key_fd = os.open(key_path, flags, 0o600)
    with os.fdopen(key_fd, "wb") as key_file:
        key_file.write(owner.serialize(save_secret_key=True))

    with ExitStack() as stack:
        db = stack.enter_context(psycopg.connect(dsn))
        if benchmark:
            # The baseline always uses the local demo database in its own session.
            baseline = stack.enter_context(psycopg.connect(DSN))
            store_plaintext_baseline(baseline, samples)
        store_readings(db, run_id, public, samples)
        payload = fetch_encrypted(db, run_id, "traffic")[0]
        verify_public_context(public, payload)
        value = samples["traffic"][0]
        if encrypt_reading(public, value) == encrypt_reading(public, value):
            raise RuntimeError("Repeated encryption produced identical bytes")
        report["security_checks"] = {
            "database_payload_requires_secret_key": True,
            "repeated_encryption_produced_distinct_ciphertexts": True,
        }

        for sensor, (_, _, unit) in SENSORS.items():
            encrypted, encrypted_metrics = measure(
                lambda: encrypted_query(db, run_id, sensor, public), repeats
            )
            total, average, smallest, largest = decrypt_results(owner, *encrypted)
            readings = samples[sensor]
            if (total, average, smallest, largest) != (
                sum(readings), Fraction(sum(readings), count), min(readings), max(readings)
            ):
                raise RuntimeError(f"Aggregate mismatch for {sensor}")
            encrypted_bytes = db.execute(
                "SELECT SUM(octet_length(payload)) FROM encrypted_readings "
                "WHERE run_id = %s AND sensor = %s", (run_id, sensor),
            ).fetchone()[0]
            entry = {
                "unit": unit,
                "results": {"sum": total, "average": float(average),
                            "min": smallest, "max": largest},
                "matches_generated_readings": True,
                "encrypted": {**encrypted_metrics, "value_payload_bytes": encrypted_bytes},
            }
            if benchmark:
                plain, metrics = measure(lambda: plaintext_query(baseline, sensor), repeats)
                p_total, p_average, p_min, p_max = plain
                if ((total, smallest, largest) != (p_total, p_min, p_max)
                        or abs(float(average) - float(p_average)) > 1e-12):
                    raise RuntimeError(f"PostgreSQL aggregate mismatch for {sensor}")
                plain_bytes = baseline.execute(
                    "SELECT SUM(pg_column_size(reading)) FROM benchmark_readings "
                    "WHERE sensor = %s", (sensor,),
                ).fetchone()[0]
                entry["matches_postgresql"] = True
                entry["plaintext"] = {**metrics, "value_payload_bytes": plain_bytes}
                entry["payload_storage_ratio"] = round(encrypted_bytes / plain_bytes, 2)
            report["sensors"][sensor] = entry
    return report


def query_saved_run(dsn, run_id, sensor):
    owner = ts.context_from((KEYS / f"{run_id}.seal").read_bytes(), n_threads=1)
    public = ts.context_from(owner.serialize(save_secret_key=False), n_threads=1)
    with psycopg.connect(dsn) as db:
        encrypted = encrypted_query(db, run_id, sensor, public)
    total, average, smallest, largest = decrypt_results(owner, *encrypted)
    return {"run_id": str(run_id), "sensor": sensor, "sum": total,
            "average": float(average), "min": smallest, "max": largest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=10, help="readings per sensor")
    parser.add_argument("--repeats", type=int, default=3, help="timed queries per sensor")
    parser.add_argument("--benchmark", action="store_true", help="compare against local SQL")
    parser.add_argument("--run-id", type=UUID, help="query a previously saved run")
    parser.add_argument("--sensor", choices=SENSORS, help="sensor to query for a saved run")
    args = parser.parse_args()
    dsn = os.environ.get("DATABASE_URL", DSN)
    if args.run_id:
        if not args.sensor or args.benchmark:
            parser.error("--run-id requires --sensor and cannot be used with --benchmark")
        print(json.dumps(query_saved_run(dsn, args.run_id, args.sensor), indent=2))
        return
    if args.sensor:
        parser.error("--sensor requires --run-id")
    if not 1 <= args.rows <= MAX_ROWS or args.repeats < 1:
        parser.error(f"--rows must be 1–{MAX_ROWS} and --repeats must be positive")
    print(json.dumps(run(dsn, args.rows, args.repeats, args.benchmark),
                     indent=2))


if __name__ == "__main__":
    main()
