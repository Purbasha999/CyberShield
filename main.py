import json
import os
import signal
import threading
import time

from modules.process_monitor import ProcessMonitor
from modules.resource_monitor import ResourceMonitor
from modules.file_monitor import FileIntegrityMonitor
from modules.login_monitor import LoginMonitor
from security.alert_manager import AlertManager
from security.event_logger import EventLogger
from dashboard.dashboard import create_app


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.json")


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def main():
    config = load_config()
    logger = EventLogger(BASE_DIR)
    alerts = AlertManager(logger)

    stop_event = threading.Event()

    monitors = [
        ProcessMonitor(config, alerts, stop_event),
        ResourceMonitor(config, alerts, stop_event),
        FileIntegrityMonitor(config, alerts, stop_event, BASE_DIR),
        LoginMonitor(config, alerts, stop_event)
    ]

    for monitor in monitors:
        monitor.start()

    app = create_app(logger, alerts, BASE_DIR)

    def shutdown(*_):
        stop_event.set()
        for monitor in monitors:
            monitor.join(timeout=2)
        logger.close()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("=" * 55)
    print("CYBERSHIELD OS")
    print("Security Monitoring Layer")
    print("=" * 55)
    print(f"Dashboard: http://{config['dashboard']['host']}:{config['dashboard']['port']}")
    print("Press Ctrl+C to stop.")
    print()

    try:
        app.run(
            host=config["dashboard"]["host"],
            port=config["dashboard"]["port"],
            debug=False,
            use_reloader=False
        )
    finally:
        shutdown()


if __name__ == "__main__":
    main()
