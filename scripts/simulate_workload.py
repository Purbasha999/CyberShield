"""Generate a varying CPU + memory workload so the dashboard charts have something to show.

CPU rises and falls in waves across several workers, and memory ramps up to a target and back
down. Everything stops on its own after --seconds (capped at 10 minutes) or on Ctrl+C.

Each process stays below CyberShield's per-process limits (CPU 80% of a core, memory 25% of RAM),
so nothing gets blocked: this script is for watching the gauges and the history chart.

    python scripts/simulate_workload.py                       # 3 min, 6 cores, up to 20% RAM
    python scripts/simulate_workload.py --seconds 300 --workers 12
"""

import argparse
import math
import multiprocessing
import os
import time

MB = 2**20
PAGE = 4096


def cpu_wave(index, workers, period, end):
    """Busy-loop with a duty cycle that follows a sine wave (5-75%); workers are phase-shifted."""
    phase = 2 * math.pi * index / workers
    start = time.time()
    while time.time() < end:
        duty = 0.4 + 0.35 * math.sin(2 * math.pi * (time.time() - start) / period + phase)
        slice_end = time.time() + 0.1 * duty
        while time.time() < slice_end:
            pass
        time.sleep(0.1 * (1 - duty))


def total_ram():
    return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")


def allocate(mb):
    chunk = bytearray(mb * MB)
    chunk[::PAGE] = b"\x01" * (len(chunk) // PAGE)  # touch every page so it really uses RAM
    return chunk


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--workers", type=int, default=6, help="CPU worker processes")
    parser.add_argument("--memory-percent", type=float, default=20, help="peak extra RAM use, %% of total (above 25 gets blocked)")
    parser.add_argument("--period", type=float, default=40, help="seconds per CPU wave")
    args = parser.parse_args()

    seconds = max(10, min(args.seconds, 600))
    workers = max(1, min(args.workers, os.cpu_count() or 1))
    peak_mb = int(total_ram() * min(max(args.memory_percent, 0), 60) / 100 / MB)
    end = time.time() + seconds

    print(f"Workload for {seconds}s: {workers} CPU worker(s), memory up to {peak_mb} MB. Ctrl+C to stop early.")
    procs = [multiprocessing.Process(target=cpu_wave, args=(i, workers, args.period, end), daemon=True)
             for i in range(workers)]
    for p in procs:
        p.start()

    chunks, chunk_mb = [], 64
    start = time.time()
    try:
        while time.time() < end:
            progress = (time.time() - start) / seconds
            # Triangle: ramp up for the first half, release during the second half.
            target_mb = peak_mb * (1 - abs(2 * progress - 1))
            while len(chunks) * chunk_mb + chunk_mb <= target_mb:
                chunks.append(allocate(chunk_mb))
            while chunks and len(chunks) * chunk_mb > target_mb:
                chunks.pop()
            remaining = int(end - time.time())
            print(f"\r  holding {len(chunks) * chunk_mb:5d} MB   {remaining:3d}s left ", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()
        chunks.clear()
        print("\nDone, CPU and memory released.")


if __name__ == "__main__":
    main()
