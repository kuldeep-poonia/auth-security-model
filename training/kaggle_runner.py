"""Kaggle Execution Script for Phase 5 LoRA Fine-Tuning & Phase 6 Evaluation.

Run this script directly inside a Kaggle notebook cell.
"""

import os
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

import argparse
import gc
import subprocess
import sys


def get_repo_root():
    """Resolve the absolute root directory of this repository and snap os.chdir to it."""
    # This file is at <repo_root>/training/kaggle_runner.py
    current_file = os.path.abspath(__file__)
    repo_root = os.path.dirname(os.path.dirname(current_file))
    os.chdir(repo_root)
    print(f"[INFO] Fixed Working Directory snapped to: {repo_root}")
    return repo_root


def setup_kaggle_environment(repo_root: str):
    """Verify GPU availability, clear stale VRAM, and install pinned dependencies."""
    print("=== Step 1: Checking GPU & Clearing Stale VRAM ===")
    import torch
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
        try:
            torch.cuda.ipc_collect()
        except Exception:
            pass
        free_bytes, total_bytes = torch.cuda.mem_get_info()
        free_gb = free_bytes / (1024 ** 3)
        total_gb = total_bytes / (1024 ** 3)
        gpu_name = torch.cuda.get_device_name(0)
        print(f"[OK] CUDA GPU Detected: {gpu_name}")
        print(f"[OK] VRAM Status: {free_gb:.2f} GB free / {total_gb:.2f} GB total")
        if free_gb < 10.0:
            print("[WARN] Less than 10 GB VRAM free! Please restart Kaggle kernel (Session -> Restart Kernel) to clear stale GPU memory.")
    else:
        print("[WARN] No GPU detected! Please ensure GPU accelerator (T4 or P100) is turned ON in Kaggle notebook settings.")

    print("=== Step 2: Removing incompatible extensions & Installing ML Dependencies ===")
    # Remove incompatible torchao 0.10.0 and unused media packages to avoid PEFT dispatcher error
    subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "torchao", "torchvision", "torchaudio"], check=False)

    cmd = [
        sys.executable, "-m", "pip", "install", "--quiet", "--upgrade",
        "transformers>=4.40.0", "peft>=0.10.0", "datasets>=2.18.0",
        "accelerate>=0.28.0", "scikit-learn>=1.4.0", "tqdm>=4.66.0"
    ]
    subprocess.check_call(cmd)
    print("[OK] ML dependencies installed.")

    target_dir = os.path.join(repo_root, "checkpoints")
    os.makedirs(target_dir, exist_ok=True)
    return target_dir


def run_training_in_kaggle(args):
    repo_root = get_repo_root()
    target_dir = setup_kaggle_environment(repo_root)

    print("=== Step 3: Launching LoRA Fine-Tuning (Native FP16, Prompt Masking) ===")
    train_script = os.path.join(repo_root, "training", "train_lora.py")
    train_file = os.path.join(repo_root, "data", "splits", "train.json")
    val_file = os.path.join(repo_root, "data", "splits", "val.json")

    cmd = [
        sys.executable,
        train_script,
        "--model_id", args.model_id,
        "--train_file", train_file,
        "--val_file", val_file,
        "--output_dir", target_dir,
        "--drive_dir", target_dir,
        "--batch_size", str(args.batch_size),
        "--gradient_accumulation_steps", str(args.gradient_accumulation_steps),
        "--learning_rate", str(args.learning_rate),
        "--epochs", str(args.epochs),
        "--save_steps", str(args.save_steps),
        "--eval_steps", str(args.eval_steps),
        "--max_length", str(args.max_length),
    ]

    if args.resume:
        cmd.append("--resume")
    if args.smoke_test:
        cmd.append("--smoke_test")

    print(f"[INFO] Executing: {' '.join(cmd)}")
    subprocess.check_call(cmd, cwd=repo_root)
    print("\n=== Fine-Tuning Completed Successfully on Kaggle! ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kaggle Fine-Tuning Runner")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen2.5-Coder-0.5B-Instruct")
    parser.add_argument("--batch_size", type=int, default=1)
    parser.add_argument("--gradient_accumulation_steps", type=int, default=16)
    parser.add_argument("--learning_rate", type=float, default=2e-4)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--save_steps", type=int, default=25)
    parser.add_argument("--eval_steps", type=int, default=25)
    parser.add_argument("--max_length", type=int, default=384)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--smoke_test", action="store_true")
    args = parser.parse_args()
    run_training_in_kaggle(args)
