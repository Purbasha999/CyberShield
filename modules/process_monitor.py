import threading
import psutil


class ProcessMonitor(threading.Thread):
    def __init__(self, config, alerts, stop_event):
        super().__init__(daemon=True, name="ProcessMonitor")
        self.threshold = config["process"]["cpu_alert_threshold"]
        self.alerts = alerts
        self.stop_event = stop_event
        self.flagged_pids = set()      # processes already reported as high-CPU
        self.lock = threading.Lock()
        self.latest = []

    def snapshot(self):
        processes = []
        over_threshold = set()

        for proc in psutil.process_iter(
            ["pid", "name", "username", "status", "cpu_percent", "memory_percent"]
        ):
            try:
                info = proc.info
                cpu = float(info.get("cpu_percent") or 0)
                memory = float(info.get("memory_percent") or 0)

                processes.append({
                    "pid": info["pid"],
                    "name": info.get("name") or "unknown",
                    "owner": info.get("username") or "unknown",
                    "status": info.get("status") or "unknown",
                    "cpu": round(cpu, 2),
                    "memory": round(memory, 2)
                })

                if cpu >= self.threshold:
                    over_threshold.add(info["pid"])
                    # Alert only when the process first crosses the threshold.
                    if info["pid"] not in self.flagged_pids:
                        self.alerts.raise_alert(
                            "PROCESS_RESOURCE",
                            "LOW",
                            f"Process {info['pid']} ({info.get('name')}) is using {cpu:.1f}% CPU",
                            {"pid": info["pid"], "cpu": cpu}
                        )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.flagged_pids = over_threshold
        processes.sort(key=lambda x: x["cpu"], reverse=True)

        with self.lock:
            self.latest = processes
        return processes

    def latest_snapshot(self):
        with self.lock:
            return list(self.latest)

    def run(self):
        while not self.stop_event.is_set():
            self.snapshot()
            self.stop_event.wait(5)
