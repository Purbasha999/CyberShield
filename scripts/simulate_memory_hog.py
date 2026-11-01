"""Hold a large block of RAM for a limited time to trigger the high-memory process alert.

    python scripts/simulate_memory_hog.py                  # one process holding 35% of RAM for 40 s
    python scripts/simulate_memory_hog.py --percent 30 --seconds 60

The memory is held by a child process, so this script can tell you afterwards whether the child
finished normally or was blocked by CyberShield (memory alert threshold: 25% of RAM).
"""

import argparse
import multiprocessing
import os
import signal
import time

MB = 2**20
PAGE = 4096


def total_ram():
    return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")


def hold(size, seconds):
    block = bytearray(size)
    block[::PAGE] = b"\x01" * (len(block) // PAGE)  # touch every page so it really uses RAM
    time.sleep(seconds)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--percent", type=float, default=35, help="share of total RAM to hold (max 60)")
    parser.add_argument("--seconds", type=int, default=40)
    args = parser.parse_args()
    size = int(total_ram() * min(max(args.percent, 1), 60) / 100) // PAGE * PAGE
    seconds = max(5, min(args.seconds, 300))

    child = multiprocessing.Process(target=hold, args=(size, seconds), name="memory-hog")
    started = time.time()
    child.start()
    print(f"PID {child.pid} is holding {size // MB} MB ({args.percent:.0f}% of RAM) for {seconds}s. "
          "Watch the Memory gauge and Top processes.")
    try:
        child.join()
    except KeyboardInterrupt:
        child.terminate()
        child.join()

    lasted = time.time() - started
    if child.exitcode in (-signal.SIGTERM, -signal.SIGKILL):
        print(f"PID {child.pid} was blocked by CyberShield after {lasted:.0f}s "
              f"({signal.Signals(-child.exitcode).name}). Memory released.")
    else:
        print(f"Finished normally after {lasted:.0f}s. Memory released.")


if __name__ == "__main__":
    main()
