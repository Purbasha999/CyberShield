"""Resource monitoring: CPU, RAM, swap, disk, load average and process count."""

import os
import socket
import time

import psutil

from security.events import LOW, SecurityEvent


class ResourceMonitor:
    name = "resource"

    def __init__(self, cfg):
        self.cfg = cfg
        self._streak = {}
        self._active = set()
        # The first cpu_percent(None) call only primes the counters and always returns 0.
        psutil.cpu_percent(None)
        psutil.cpu_percent(None, percpu=True)

    def _check(self, metric, value, threshold, sustain, label, details, events):
        streak = self._streak.get(metric, 0) + 1 if value >= threshold else 0
        self._streak[metric] = streak
        if streak >= sustain:
            if metric not in self._active:
                self._active.add(metric)
                events.append(
                    SecurityEvent(
                        module=self.name,
                        severity=LOW,
                        title=f"High {label} utilization",
                        details={"value": round(value, 1), "threshold": threshold, **details},
                        key=f"resource:{metric}",
                    )
                )
        else:
            self._active.discard(metric)

    def poll(self):
        events = []
        sustain = max(1, int(self.cfg["sustain_polls"]))
        cpu = psutil.cpu_percent(None)
        per_cpu = psutil.cpu_percent(None, percpu=True)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        net = psutil.net_io_counters()
        try:
            load = [round(x, 2) for x in os.getloadavg()]
        except (AttributeError, OSError):
            load = None

        disks = []
        for path in self.cfg["disk_paths"]:
            try:
                usage = psutil.disk_usage(path)
            except OSError:
                continue
            disks.append(
                {"path": path, "percent": usage.percent, "used": usage.used, "total": usage.total, "free": usage.free}
            )

        self._check("cpu", cpu, self.cfg["cpu_threshold"], sustain, "CPU", {}, events)
        self._check(
            "memory", mem.percent, self.cfg["memory_threshold"], sustain, "RAM",
            {"used_mb": mem.used // 2**20, "total_mb": mem.total // 2**20}, events,
        )
        for d in disks:
            # Disk usage changes slowly, so no need to wait for several polls.
            self._check(f"disk:{d['path']}", d["percent"], self.cfg["disk_threshold"], 1, "disk", {"path": d["path"]}, events)

        snapshot = {
            "hostname": socket.gethostname(),
            "cpu_percent": cpu,
            "per_cpu": per_cpu,
            "cpu_count": psutil.cpu_count(),
            "memory": {"percent": mem.percent, "used": mem.used, "total": mem.total, "available": mem.available},
            "swap": {"percent": swap.percent, "used": swap.used, "total": swap.total},
            "disks": disks,
            "disk_percent": disks[0]["percent"] if disks else 0.0,
            "process_count": len(psutil.pids()),
            "load_average": load,
            "uptime_seconds": int(time.time() - psutil.boot_time()),
            "net": {"bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv},
            "thresholds": {
                "cpu": self.cfg["cpu_threshold"],
                "memory": self.cfg["memory_threshold"],
                "disk": self.cfg["disk_threshold"],
            },
        }
        return snapshot, events
