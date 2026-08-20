import argparse
import glob
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
    DataCollatorForSeq2Seq,
)
from peft import LoraConfig, get_peft_model, TaskType

from training.logger import ExperimentLogger
from training.dataset_formatter import load_and_format_dataset

# Target projection modules for Qwen2.5 / LLaMA architecture
DEFAULT_TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]


def verify_gpu_bnb() -> bool:
    """Verify CUDA availability and bitsandbytes 4-bit quantized layer on GPU."""
    print("--- GPU & BitsAndBytes Verification ---")
    try:
        if not torch.cuda.is_available():
            print("[WARN] CUDA is not available. BitsAndBytes 4-bit GPU acceleration requires a CUDA-capable GPU.")
            return False
        
        gpu_name = torch.cuda.get_device_name(0)
        vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        print(f"[OK] CUDA detected: {gpu_name} ({vram_gb:.2f} GB VRAM)")
        
        import bitsandbytes as bnb
        layer = bnb.nn.Linear4bit(32, 32, bias=False, compute_dtype=torch.float16).cuda()
        x = torch.randn(2, 32, dtype=torch.float16).cuda()
        out = layer(x)
        print(f"[OK] BitsAndBytes 4-bit layer successfully executed forward pass on GPU: shape {out.shape}")
        return True
    except Exception as e:
        print(f"[FAIL] BitsAndBytes GPU check failed with error: {e}")
        return False


def find_latest_checkpoint(checkpoint_dir: str) -> Optional[str]:
    """Find the most recent checkpoint directory by step number."""
    if not os.path.exists(checkpoint_dir):
        return None
    checkpoint_dirs = glob.glob(os.path.join(checkpoint_dir, "checkpoint-*"))
    if not checkpoint_dirs:
        return None

    def get_step(path: str) -> int:
        match = re.search(r"checkpoint-(\d+)", path)
        return int(match.group(1)) if match else -1

    valid_checkpoints = [ckpt for ckpt in checkpoint_dirs if get_step(ckpt) >= 0]
    if not valid_checkpoints:
        return None
    return max(valid_checkpoints, key=get_step)


class SecurityDataset(torch.utils.data.Dataset):
    """PyTorch dataset tokenizing ChatML messages for causal LM fine-tuning."""

    def __init__(self, formatted_items: List[Dict[str, Any]], tokenizer: Any, max_length: int = 1024):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.examples = []

        for item in formatted_items:
            messages = item["messages"]
            # Apply chat template
            if hasattr(tokenizer, "apply_chat_template"):
                prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
            else:
                prompt = "\n".join(f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>" for m in messages)

            tokens = tokenizer(
                prompt,
                truncation=True,
                max_length=max_length,
                padding=False,
                return_tensors=None,
            )
            input_ids = tokens["input_ids"]
            attention_mask = tokens["attention_mask"]
            labels = list(input_ids)  # Standard causal LM prediction

            self.examples.append({
                "input_ids": input_ids,
                "attention_mask": attention_mask,
                "labels": labels,
            })

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        return self.examples[idx]


def train(args):
    target_dir = args.drive_dir if args.drive_dir else args.output_dir
    os.makedirs(target_dir, exist_ok=True)

    logger = ExperimentLogger(run_name=f"train_{os.path.basename(args.model_id)}")
    logger.log_config(vars(args))

    print(f"[INFO] Initializing tokenizer for: {args.model_id}")
    tokenizer = AutoTokenizer.from_pretrained(args.model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print("[INFO] Loading datasets...")
    train_items = load_and_format_dataset(args.train_file)
    val_items = load_and_format_dataset(args.val_file) if os.path.exists(args.val_file) else []

    if args.smoke_test:
        print("[INFO] Running in smoke-test mode (subset: 10 train, 4 val)...")
        train_items = train_items[:10]
        val_items = val_items[:4]
        args.max_steps = 2
        args.save_steps = 2
        args.eval_steps = 2
        if not torch.cuda.is_available():
            args.max_length = min(args.max_length, 128)
            args.batch_size = 1
            args.gradient_accumulation_steps = 1

    train_dataset = SecurityDataset(train_items, tokenizer, max_length=args.max_length)
    val_dataset = SecurityDataset(val_items, tokenizer, max_length=args.max_length) if val_items else None

    print(f"[INFO] Train dataset size: {len(train_dataset)}, Val dataset size: {len(val_dataset) if val_dataset else 0}")

    # Configure Quantization / Model Loading
    device_map = "auto" if torch.cuda.is_available() else None
    torch_dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else (torch.float16 if torch.cuda.is_available() else torch.float32)

    print(f"[INFO] Loading base model: {args.model_id} (dtype={torch_dtype}, cuda={torch.cuda.is_available()})")
    model = AutoModelForCausalLM.from_pretrained(
        args.model_id,
        torch_dtype=torch_dtype,
        device_map=device_map,
        trust_remote_code=True,
    )

    # Configure LoRA
    print(f"[INFO] Setting up LoRA (r={args.lora_r}, alpha={args.lora_alpha}, target_modules={DEFAULT_TARGET_MODULES})")
    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        target_modules=DEFAULT_TARGET_MODULES,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # Construct TrainingArguments safely across transformers versions
    import inspect
    sig = inspect.signature(TrainingArguments.__init__).parameters
    training_kwargs = {
        "output_dir": target_dir,
        "per_device_train_batch_size": args.batch_size,
        "gradient_accumulation_steps": args.gradient_accumulation_steps,
        "learning_rate": args.learning_rate,
        "lr_scheduler_type": "cosine",
        "num_train_epochs": args.epochs if not args.smoke_test else 1,
        "max_steps": args.max_steps if (args.max_steps and args.max_steps > 0) else -1,
        "logging_steps": 1 if args.smoke_test else 10,
        "save_strategy": "steps",
        "save_steps": args.save_steps,
        "save_total_limit": 3,
        "fp16": (torch_dtype == torch.float16),
        "bf16": (torch_dtype == torch.bfloat16),
        "report_to": "none",
        "dataloader_num_workers": 0,
        "dataloader_pin_memory": torch.cuda.is_available(),
    }

    eval_val = "no" if args.smoke_test else ("steps" if val_dataset else "no")
    if "eval_strategy" in sig:
        training_kwargs["eval_strategy"] = eval_val
    elif "evaluation_strategy" in sig:
        training_kwargs["evaluation_strategy"] = eval_val

    if val_dataset and not args.smoke_test:
        training_kwargs["eval_steps"] = args.eval_steps

    if "warmup_ratio" in sig:
        training_kwargs["warmup_ratio"] = 0.03
    elif "warmup_steps" in sig:
        training_kwargs["warmup_steps"] = 20

    filtered_training_kwargs = {k: v for k, v in training_kwargs.items() if k in sig}
    training_args = TrainingArguments(**filtered_training_kwargs)

    data_collator = DataCollatorForSeq2Seq(tokenizer, pad_to_multiple_of=8, return_tensors="pt", padding=True)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        data_collator=data_collator,
    )

    latest_ckpt = find_latest_checkpoint(target_dir) if args.resume else None
    if args.resume and latest_ckpt:
        print(f"[INFO] Resuming training from checkpoint: {latest_ckpt}")
        logger.log_event("resume", {"checkpoint": latest_ckpt})
        train_result = trainer.train(resume_from_checkpoint=latest_ckpt)
    else:
        print("[INFO] Starting training from scratch...")
        train_result = trainer.train()

    # Save final model adapter and tokenizer
    final_adapter_dir = os.path.join(target_dir, "final_adapter")
    trainer.save_model(final_adapter_dir)
    tokenizer.save_pretrained(final_adapter_dir)

    metrics = train_result.metrics
    logger.log_event("train_complete", metrics)
    print(f"[OK] Fine-tuning finished! Final adapter saved to {final_adapter_dir}")
    return metrics


def parse_args():
    parser = argparse.ArgumentParser(description="LoRA/QLoRA Fine-Tuning Pipeline for Auth/Authz Security Model")
    parser.add_argument(
        "--model_id",
        type=str,
        default="Qwen/Qwen2.5-Coder-0.5B-Instruct",
        help="Hugging Face base model identifier",
    )
    parser.add_argument(
        "--train_file",
        type=str,
        default="data/splits/train.json",
        help="Path to training partition JSON",
    )
    parser.add_argument(
        "--val_file",
        type=str,
        default="data/splits/val.json",
        help="Path to validation partition JSON",
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="checkpoints",
        help="Directory to store model checkpoints and adapters",
    )
    parser.add_argument(
        "--drive_dir",
        type=str,
        default=None,
        help="Optional Google Drive path for automatic artifact synchronization",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume training from the latest checkpoint in output_dir",
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=4,
        help="Batch size per device",
    )
    parser.add_argument(
        "--gradient_accumulation_steps",
        type=int,
        default=4,
        help="Number of gradient accumulation steps",
    )
    parser.add_argument(
        "--learning_rate",
        type=float,
        default=2e-4,
        help="Learning rate",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs",
    )
    parser.add_argument(
        "--max_steps",
        type=int,
        default=-1,
        help="Maximum training steps (-1 for full epoch training)",
    )
    parser.add_argument(
        "--save_steps",
        type=int,
        default=50,
        help="Checkpoint save interval in steps",
    )
    parser.add_argument(
        "--eval_steps",
        type=int,
        default=50,
        help="Evaluation interval in steps",
    )
    parser.add_argument(
        "--max_length",
        type=int,
        default=1024,
        help="Maximum tokenized sequence length",
    )
    parser.add_argument(
        "--lora_r",
        type=int,
        default=16,
        help="LoRA rank dimension",
    )
    parser.add_argument(
        "--lora_alpha",
        type=int,
        default=32,
        help="LoRA alpha scaling factor",
    )
    parser.add_argument(
        "--smoke_test",
        action="store_true",
        help="Run a 2-step plumbing check on a 10-item subset",
    )
    parser.add_argument(
        "--check_gpu_bnb",
        action="store_true",
        help="Run GPU and bitsandbytes 4-bit kernel verification and exit",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.check_gpu_bnb:
        success = verify_gpu_bnb()
        sys.exit(0 if success else 1)
    train(args)
