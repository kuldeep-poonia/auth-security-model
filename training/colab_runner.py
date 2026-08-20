"""Google Colab Execution Script for Phase 5 LoRA Fine-Tuning.

This script can be executed directly inside a Google Colab notebook cell:
!python training/colab_runner.py --repo_url <YOUR_GITHUB_REPO_URL>
"""

import argparse
import os
import subprocess
import sys


def setup_colab_environment(drive_base_dir: str = "/content/drive/MyDrive/auth_sec_model"):
    """Mount Google Drive, install pinned dependencies, and prepare paths."""
    print("=== Step 1: Mounting Google Drive ===")
    try:
        from google.colab import drive
        drive.mount("/content/drive")
        print(f"[OK] Google Drive mounted. Target checkpoint folder: {drive_base_dir}")
        os.makedirs(drive_base_dir, exist_ok=True)
    except ImportError:
        print("[WARN] google.colab not available. Running in standalone local mode.")
        drive_base_dir = "checkpoints"
        os.makedirs(drive_base_dir, exist_ok=True)

    print("=== Step 2: Installing Pinned Dependencies ===")
    req_path = "requirements-lock.txt"
    if os.path.exists(req_path):
        cmd = [sys.executable, "-m", "pip", "install", "-r", req_path]
        subprocess.check_call(cmd)
        print("[OK] Pinned dependencies successfully installed.")

    return drive_base_dir


def run_training_in_colab(args):
    drive_dir = setup_colab_environment()

    print("=== Step 3: Verifying GPU & BitsAndBytes ===")
    gpu_check_cmd = [sys.executable, "training/train_lora.py", "--check_gpu_bnb"]
    try:
        subprocess.check_call(gpu_check_cmd)
    except subprocess.CalledProcessError:
        print("[WARN] GPU verification returned non-zero. Proceeding with standard execution.")

    print("=== Step 4: Launching LoRA Fine-Tuning ===")
    cmd = [
        sys.executable,
        "training/train_lora.py",
        "--model_id", args.model_id,
        "--train_file", "data/splits/train.json",
        "--val_file", "data/splits/val.json",
        "--output_dir", "checkpoints",
        "--drive_dir", drive_dir,
        "--batch_size", str(args.batch_size),
        "--gradient_accumulation_steps", str(args.gradient_accumulation_steps),
        "--learning_rate", str(args.learning_rate),
        "--epochs", str(args.epochs),
        "--save_steps", "50",
        "--eval_steps", "50",
    ]

    if args.resume:
        cmd.append("--resume")
    if args.smoke_test:
        cmd.append("--smoke_test")

    print(f"[INFO] Executing command: {' '.join(cmd)}")
    subprocess.check_call(cmd)
    print("=== Fine-Tuning Run Completed Successfully! ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Colab Fine-Tuning Runner")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen2.5-Coder-0.5B-Instruct")
    parser.add_argument("--batch_size", type=int, default=4)
    parser.add_argument("--gradient_accumulation_steps", type=int, default=4)
    parser.add_argument("--learning_rate", type=float, default=2e-4)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--smoke_test", action="store_true")
    args = parser.parse_args()
    run_training_in_colab(args)
