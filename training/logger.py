import datetime
import json
import os
import platform
import psutil
from typing import Any, Dict, Optional


class ExperimentLogger:
    """Structured JSONL run logger for training and data experiments."""

    def __init__(self, run_name: str, log_dir: str = "runs"):
        self.run_name = run_name
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, f"{self.run_name}.jsonl")
        self._record_system_environment()

    def _write_record(self, record_type: str, payload: Dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "run_name": self.run_name,
            "type": record_type,
            "data": payload,
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _record_system_environment(self) -> None:
        env_data = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        }
        try:
            import torch
            env_data["torch_version"] = torch.__version__
            env_data["cuda_available"] = torch.cuda.is_available()
            if torch.cuda.is_available():
                env_data["gpu_name"] = torch.cuda.get_device_name(0)
                env_data["gpu_vram_gb"] = round(
                    torch.cuda.get_device_properties(0).total_memory / (1024**3), 2
                )
        except ImportError:
            env_data["torch_version"] = "not_installed"

        self._write_record("environment", env_data)

    def log_config(self, config: Dict[str, Any]) -> None:
        """Record model and training hyperparameters."""
        self._write_record("hyperparameters", config)

    def log_metrics(self, step: int, metrics: Dict[str, Any], epoch: Optional[float] = None) -> None:
        """Record intermediate step/epoch metrics."""
        payload = {"step": step, "metrics": metrics}
        if epoch is not None:
            payload["epoch"] = epoch
        self._write_record("metrics", payload)

    def log_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Record an arbitrary custom event."""
        self._write_record(event_type, data)

    def log_checkpoint(self, step: int, checkpoint_path: str) -> None:
        """Record saved checkpoint path."""
        self._write_record("checkpoint", {"step": step, "checkpoint_path": checkpoint_path})

    def log_summary(self, status: str, final_metrics: Optional[Dict[str, Any]] = None) -> None:
        """Record run completion status and final metric summary."""
        payload = {"status": status}
        if final_metrics:
            payload["final_metrics"] = final_metrics
        self._write_record("summary", payload)
