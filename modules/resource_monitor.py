import threading
import psutil


class ResourceMonitor(threading.Thread):
    def __init__(self, config, alerts, stop_event):
        super().__init__(daemon=True, name="ResourceMonitor")
        self.config = config["resource"]
        self.alerts = alerts
        self.stop_event = stop_event

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

        if cpu >= self.config["cpu_alert_threshold"]:
            self.alerts.raise_alert(
                "RESOURCE_USAGE", "LOW",
                f"CPU utilization is {cpu:.1f}%",
                result
            )

        if memory >= self.config["memory_alert_threshold"]:
            self.alerts.raise_alert(
                "RESOURCE_USAGE", "LOW",
                f"Memory utilization is {memory:.1f}%",
                result
            )

        if disk >= self.config["disk_alert_threshold"]:
            self.alerts.raise_alert(
                "RESOURCE_USAGE", "LOW",
                f"Disk utilization is {disk:.1f}%",
                result
            )

        return result

    def run(self):
        while not self.stop_event.is_set():
            self.snapshot()
            self.stop_event.wait(5)
