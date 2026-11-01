"""Burn CPU for a limited time to trigger the high-CPU alerts.

    python scripts/simulate_cpu_load.py               # 1 worker at 100% of a core -> process alert + BLOCKED
    python scripts/simulate_cpu_load.py --workers 4   # 4 workers -> 4 processes blocked, one popup
    python scripts/simulate_cpu_load.py --spread      # whole CPU at ~100%, but each process stays near 50%
                                                      #   -> system "High CPU utilization" alert, nothing blocked

Each worker is a separate process busy-looping (`while True: pass`). At the end the script reports
which workers ran to completion and which were stopped by CyberShield.
"""

import argparse
import multiprocessing
import os
import signal
import time


def burn(seconds):
    end = time.time() + seconds
    while time.time() < end:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--spread", action="store_true",
                        help="run 2 workers per core so the system is busy but no single process is")
    args = parser.parse_args()
    seconds = max(1, min(args.seconds, 300))  # hard cap so it can never run away
    cores = os.cpu_count() or 1
    workers = cores * 2 if args.spread else max(1, min(args.workers, cores))

    print(f"Burning CPU with {workers} worker(s) for {seconds}s. Watch the CPU gauge and Top processes.")
    procs = [multiprocessing.Process(target=burn, args=(seconds,)) for _ in range(workers)]
    for p in procs:
        p.start()
    if workers <= 12:
        print("  worker PIDs:", " ".join(str(p.pid) for p in procs))
    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()
            p.join()

    stopped = [p for p in procs if p.exitcode in (-signal.SIGTERM, -signal.SIGKILL)]
    print(f"Done. {workers - len(stopped)} worker(s) finished normally, {len(stopped)} stopped by CyberShield.")
    for p in stopped:
        print(f"  PID {p.pid} was blocked ({signal.Signals(-p.exitcode).name})")


if __name__ == "__main__":
    main()
