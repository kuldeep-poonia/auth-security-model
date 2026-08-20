"""Kaggle Execution Script for Phase 5 LoRA Fine-Tuning & Phase 6 Evaluation.

Run this script directly inside a Kaggle notebook cell.
"""

import os
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

import argparse
import subprocess
import sys


def setup_kaggle_environment():
    """Verify GPU availability and install pinned dependencies for Kaggle environment."""
    print("=== Step 1: Checking Kaggle GPU Environment ===")
    import torch
    if torch.cuda.is_available():
        gpu_name = torch.cuda.get_device_name(0)
        vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
        print(f"[OK] CUDA GPU Detected: {gpu_name} ({vram_gb:.2f} GB VRAM)")
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

    os.makedirs("checkpoints", exist_ok=True)
    return "checkpoints"


def run_training_in_kaggle(args):
    target_dir = setup_kaggle_environment()

    print("=== Step 3: Launching LoRA Fine-Tuning (Native FP16, Prompt Masking) ===")
    cmd = [
        sys.executable,
        "training/train_lora.py",
        "--model_id", args.model_id,
        "--train_file", "data/splits/train.json",
        "--val_file", "data/splits/val.json",
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
    subprocess.check_call(cmd)
    print("\n=== Fine-Tuning Completed Successfully on Kaggle! ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kaggle Fine-Tuning Runner")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen2.5-Coder-0.5B-Instruct")
    parser.add_argument("--batch_size", type=int, default=2)
    parser.add_argument("--gradient_accumulation_steps", type=int, default=4)
    parser.add_argument("--learning_rate", type=float, default=2e-4)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--save_steps", type=int, default=50)
    parser.add_argument("--eval_steps", type=int, default=50)
    parser.add_argument("--max_length", type=int, default=384)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--smoke_test", action="store_true")
    args = parser.parse_args()
    run_training_in_kaggle(args)
