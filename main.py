"""CyberShield OS - security monitoring layer for Linux.

Usage:
    python main.py                  # web dashboard on http://127.0.0.1:8080
    python main.py --mode terminal  # live terminal dashboard
    python main.py --once           # one scan, print a report, exit
    python main.py --rebaseline     # accept current file state as the new integrity baseline
"""

import argparse
import logging
import signal
import sys
import time

from config.loader import ConfigError, load_config
from dashboard import terminal
from dashboard.dashboard import serve_in_background
from security.engine import SecurityEngine


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="CyberShield OS security monitor")
    parser.add_argument("--config", help="path to config.json (default: config/config.json)")
    parser.add_argument("--mode", choices=["web", "terminal"], default="web")
    parser.add_argument("--host", help="dashboard bind address (default from config)")
    parser.add_argument("--port", type=int, help="dashboard port (default from config)")
    parser.add_argument("--once", action="store_true", help="run every monitor once, print a report and exit")
    parser.add_argument("--rebaseline", action="store_true", help="reset the file-integrity baseline and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser.parse_args(argv)


def _interrupt(signum, frame):
    # Turn SIGTERM (e.g. `kill`) into the same clean shutdown as Ctrl+C.
    raise KeyboardInterrupt


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if sys.platform != "linux":
        print("Warning: CyberShield is designed for Linux (/proc, /var/log/auth.log). Some modules may not work.")

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Config error: {exc}")
        return 2
    if args.host:
        config["dashboard"]["host"] = args.host
    if args.port:
        config["dashboard"]["port"] = args.port

    engine = SecurityEngine(config)

    if args.rebaseline:
        engine.rebaseline_files()
        files = engine.get_state()["modules"].get("file", {}).get("snapshot") or {}
        print(f"File-integrity baseline reset: {files.get('total_files', 0)} files recorded.")
        engine.stop()
        return 0

    if args.once:
        engine.run_once()
        time.sleep(1)  # CPU percentages need two samples
        engine.run_once()
        print(terminal.render(engine.get_state(), color=sys.stdout.isatty()))
        engine.stop()
        return 0

    signal.signal(signal.SIGTERM, _interrupt)
    engine.start()
    print(f"CyberShield OS running. Data, logs and database in {config['data_dir']}")
    try:
        if args.mode == "terminal":
            terminal.run(engine, config["dashboard"]["refresh_seconds"])
        else:
            host, port = config["dashboard"]["host"], config["dashboard"]["port"]
            try:
                server, _ = serve_in_background(engine, host, port)
            except OSError as exc:
                print(f"Cannot start dashboard on {host}:{port}: {exc}. Try --port 8090.")
                return 1
            print(f"Dashboard: http://{'localhost' if host in ('127.0.0.1', '0.0.0.0') else host}:{port}  (Ctrl+C to stop)")
            try:
                while True:
                    time.sleep(1)
            finally:
                server.shutdown()
    except KeyboardInterrupt:
        pass
    finally:
        print("\nStopping CyberShield...")
        engine.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
