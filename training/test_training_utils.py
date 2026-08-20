import json
import os
import shutil
import tempfile
import pytest

from training.logger import ExperimentLogger
from training.train_lora import find_latest_checkpoint


def test_logger_writes_jsonl_records():
    temp_dir = tempfile.mkdtemp()
    try:
        logger = ExperimentLogger(run_name="unit_test_run", log_dir=temp_dir)
        logger.log_config({"learning_rate": 0.0002, "lora_r": 16})
        logger.log_metrics(step=10, metrics={"loss": 0.45})
        logger.log_checkpoint(step=10, checkpoint_path=os.path.join(temp_dir, "checkpoint-10"))
        logger.log_summary(status="completed", final_metrics={"val_loss": 0.42})

        log_path = os.path.join(temp_dir, "unit_test_run.jsonl")
        assert os.path.exists(log_path)

        with open(log_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        # Check records: environment, hyperparameters, metrics, checkpoint, summary
        record_types = [r["type"] for r in lines]
        assert "environment" in record_types
        assert "hyperparameters" in record_types
        assert "metrics" in record_types
        assert "checkpoint" in record_types
        assert "summary" in record_types

        # Verify environment data has required system info
        env_record = next(r for r in lines if r["type"] == "environment")
        assert "platform" in env_record["data"]
        assert "cpu_count_logical" in env_record["data"]
        assert "total_ram_gb" in env_record["data"]
    finally:
        shutil.rmtree(temp_dir)


def test_find_latest_checkpoint_ordering():
    temp_dir = tempfile.mkdtemp()
    try:
        os.makedirs(os.path.join(temp_dir, "checkpoint-10"))
        os.makedirs(os.path.join(temp_dir, "checkpoint-50"))
        os.makedirs(os.path.join(temp_dir, "checkpoint-200"))
        os.makedirs(os.path.join(temp_dir, "checkpoint-30"))

        latest = find_latest_checkpoint(temp_dir)
        assert latest is not None
        assert latest.endswith("checkpoint-200")
    finally:
        shutil.rmtree(temp_dir)


def test_find_latest_checkpoint_empty_or_nonexistent():
    temp_dir = tempfile.mkdtemp()
    try:
        assert find_latest_checkpoint(temp_dir) is None
        assert find_latest_checkpoint(os.path.join(temp_dir, "nonexistent")) is None
    finally:
        shutil.rmtree(temp_dir)
