# Homomorphic Encryption for Smart City IoT Databases

A small Python command-line project for Project No. 15. It generates simulated traffic, air-quality, parking, street-light and temperature readings, encrypts each reading with TenSEAL BFV, and stores the ciphertext in PostgreSQL. A comparison mode measures the cost of encrypted queries against conventional PostgreSQL aggregates.

## What is in the project

| File | What it does |
| --- | --- |
| `demo.py` | Generates sensor readings, connects to PostgreSQL, runs encrypted queries, and prints the results and benchmark as JSON. |
| `crypto.py` | Creates BFV keys, encrypts readings, performs homomorphic aggregation, and decrypts the results for the trusted client. |
| `test_crypto.py` | Tests the encrypted calculations, input limits, and key separation without a database. |
| `compose.yaml` | Starts a local PostgreSQL 16 server with Docker Compose. |
| `requirements.txt` | Lists TenSEAL for encryption, NumPy, Psycopg for PostgreSQL, and psutil for memory measurements. |
| `.gitignore` | Excludes private keys, the virtual environment, and generated ZIP archives from Git. |

## 1. Install the Python dependencies

Install **64-bit Python 3.11**. Extract the ZIP and open PowerShell in the folder containing `demo.py`. Create a virtual environment and install the dependencies. The commands use the virtual environment's Python directly, so PowerShell activation is optional.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest -v
```

If the `py` command is unavailable, use `python -m venv .venv` after checking that `python --version` reports Python 3.11. If pip cannot find TenSEAL, check that the virtual environment uses 64-bit Python 3.11 and can access PyPI.

## 2. Set up PostgreSQL

Choose one setup. Both use the local database `smart_city`, the user `city`, the demo password `local_demo`, and port `5432`. The app creates the encrypted readings table on its first run.

### Option A. Docker Desktop

Open Docker Desktop and wait for it to start. From the project folder, run the following commands. The Compose file creates the database and login automatically.

```powershell
docker compose up -d
docker compose exec db pg_isready -h 127.0.0.1 -U city -d smart_city
```

Repeat the readiness check until it prints `accepting connections`. If port 5432 is already in use by a local PostgreSQL server, use Option B.

### Option B. Local PostgreSQL without Docker

Install PostgreSQL if you do not already have it, and make sure its Windows service is running on port 5432. Open **SQL Shell (psql)** and connect to `localhost`, database `postgres`, as the `postgres` administrator. Use the administrator password you chose during installation. Run the following SQL statements once for a fresh setup.

```sql
CREATE ROLE city LOGIN PASSWORD 'local_demo';
CREATE DATABASE smart_city OWNER city;
```

Type `\q` to exit the SQL Shell. If the credentials or port differ, set `DATABASE_URL` in the PowerShell session before running the demo. Benchmark mode still requires the default local setup for its plaintext comparison.

```powershell
$env:DATABASE_URL = "postgresql://YOUR_USER:YOUR_PASSWORD@localhost:5432/YOUR_DATABASE"
```

For a remote database, use a dedicated database and a TLS-verified connection. Keep credentials and the generated `keys/` files private.

## 3. Run the demo and check the output

```powershell
.\.venv\Scripts\python.exe demo.py
```

The default run generates 10 readings for each of five sensors. The JSON includes a `run_id`, a `security_checks` section, and a result for each sensor with `sum`, `average`, `min`, and `max`. Check that `matches_generated_readings` and both security checks are `true`.

To compare encrypted queries with normal PostgreSQL aggregates, run the benchmark. Check that `matches_postgresql` is `true` for each sensor.

```powershell
.\.venv\Scripts\python.exe demo.py --rows 10 --repeats 3 --benchmark
```

### Query a saved run

Replace `YOUR-RUN-UUID` with the actual `run_id` printed in the JSON.

```powershell
.\.venv\Scripts\python.exe demo.py --run-id YOUR-RUN-UUID --sensor traffic
```

Supported sensor names are `traffic`, `air_quality`, `parking`, `street_light` and `temperature`. Use `--rows` from 1 to 1,000 per sensor. Each run creates fresh keys. The corresponding private context in `keys/` is required to reopen a run. Keep those files private.

When you're finished, run `docker compose down` if you used Docker. The named volume keeps your stored readings for the next session.

## How it works

1. Python generates whole-number readings in the range 0–100. For a reading of 24, it creates a 101-slot vector with a 1 at index 24 and zeros everywhere else.
2. Python encrypts the vector before sending it to PostgreSQL. PostgreSQL stores the serialized ciphertext in a `BYTEA` column with a public sensor label and run ID.
3. A Python evaluator fetches the rows and adds the vectors while encrypted. The resulting ciphertext represents a frequency histogram. Its encrypted dot product with the public weights 0–100 yields an encrypted sum.
4. The trusted client decrypts the sum and histogram. It divides the sum by the row count for the average and finds the first and last occupied bins for exact minimum and maximum. For readings 10, 20, 20 and 40, the sum is 90, the average is 22.5, the minimum is 10 and the maximum is 40.

**MIN and MAX design:** The evaluator performs histogram aggregation without a secret key. The final selection of endpoints runs on the trusted client after aggregate decryption. This demonstration uses a bounded-integer encoding and does not implement standalone ciphertext-to-ciphertext MIN/MAX comparisons. The trusted client receives the histogram, which reveals aggregate frequencies. The CLI demonstrates the client and evaluator roles in one local Python process.

## Benchmark and security checks

- `--benchmark` inserts the same synthetic readings into a temporary table in a separate connection to the default **local** database. That session closes after the benchmark. The encrypted database can be remote through `DATABASE_URL`. A normal run skips the plaintext table.
- The report checks all four results against the generated readings and, in benchmark mode, PostgreSQL's `SUM`, `AVG`, `MIN` and `MAX`. Use `--rows 10`, `--rows 50` and `--rows 100` for a comparison across input sizes.
- Mean wall time includes the database request and, on the encrypted path, row transfer and homomorphic aggregation. Key generation, ingestion and result decryption are outside query timing. CPU time and sampled resident memory describe the Python process. They exclude PostgreSQL server resources and can miss transient memory peaks.
- Storage compares serialized value payload bytes against PostgreSQL integer value bytes. The ratio excludes table/index overhead and the client's key files.
- Every demo verifies that a public-only context fails to decrypt a stored payload and that encrypting the same value twice yields different bytes. A database reader can still see sensor labels, run IDs, and row counts. The demo does not authenticate ciphertext or detect all tampering. Real deployment also requires access controls, encrypted transport and protected client keys.
- Local demo credentials, synthetic readings, and a CLI keep the project small enough to present in class. Docker is optional. No sensor hardware is needed.

See [TenSEAL](https://github.com/OpenMined/TenSEAL) for BFV operations and the library API.

## Upload to GitHub

Create an empty GitHub repository, then run these commands in the project folder. Replace the example URL with your repository URL.

```powershell
git init -b main
git add .
git commit -m "Add encrypted smart city sensor demo"
git remote add origin https://github.com/YOUR-USERNAME/applied-crypto-project.git
git push -u origin main
```
