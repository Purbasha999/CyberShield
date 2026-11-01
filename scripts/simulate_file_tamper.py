"""Modify, create, chmod and delete files in the demo watch folder to trigger integrity alerts.

Only touches ~/cybershield_watch (or --dir). Never point it at real system files.
"""

import argparse
import os
import time
from pathlib import Path


def step(message, pause):
    print(f"  {message}")
    time.sleep(pause)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default="~/cybershield_watch")
    parser.add_argument("--pause", type=float, default=12, help="seconds between steps (>= file monitor interval)")
    args = parser.parse_args()
    folder = Path(args.dir).expanduser()
    folder.mkdir(parents=True, exist_ok=True)

    target = folder / "important.txt"
    if not target.exists():
        target.write_text("Quarterly results: CONFIDENTIAL\n")
        print(f"Created {target}; waiting for it to be baselined...")
        time.sleep(args.pause)

    print(f"Tampering with files in {folder}:")
    with open(target, "a") as fh:
        fh.write(f"injected line {time.ctime()}\n")
    step("modified important.txt          -> expect MEDIUM 'File modification detected'", args.pause)

    dropped = folder / "backdoor.sh"
    dropped.write_text("#!/bin/sh\necho owned\n")
    step("created backdoor.sh             -> expect LOW 'New file detected'", args.pause)

    os.chmod(dropped, 0o777)
    step("chmod 777 backdoor.sh           -> expect MEDIUM 'File permissions changed'", args.pause)

    dropped.unlink()
    step("deleted backdoor.sh             -> expect MEDIUM 'Monitored file deleted'", 0)
    print("Done. Use 'Accept current state' on the dashboard to trust the new important.txt.")


if __name__ == "__main__":
    main()
