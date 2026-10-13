import threading
import psutil


class ResourceMonitor(threading.Thread):
    LABELS = {"cpu": "CPU", "memory": "Memory", "disk": "Disk"}

    def __init__(self, config, alerts, stop_event):
        super().__init__(daemon=True, name="ResourceMonitor")
        self.config = config["resource"]
        self.alerts = alerts
        self.stop_event = stop_event
        self.active = set()            # metrics currently above threshold
        self.lock = threading.Lock()
        self.latest = {"cpu": 0, "memory": 0, "disk": 0, "processes": 0}

    def snapshot(self):
        cpu = psutil.cpu_percent(interval=0.2)
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        processes = len(psutil.pids())

        result = {
            "cpu": round(cpu, 2),
            "memory": round(memory, 2),
            "disk": round(disk, 2),
            "processes": processes
        }

        for metric, value in (("cpu", cpu), ("memory", memory), ("disk", disk)):
            if value >= self.config[f"{metric}_alert_threshold"]:
                # Alert only when the metric first crosses the threshold.
                if metric not in self.active:
                    self.active.add(metric)
                    self.alerts.raise_alert(
                        "RESOURCE_USAGE", "LOW",
                        f"{self.LABELS[metric]} utilization is {value:.1f}%",
                        result
                    )
            else:
                self.active.discard(metric)

        with self.lock:
            self.latest = result
        return result

    def latest_snapshot(self):
        with self.lock:
            return dict(self.latest)

    def run(self):
        while not self.stop_event.is_set():
            self.snapshot()
            self.stop_event.wait(5)
