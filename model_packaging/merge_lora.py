"""LoRA Adapter Merge Script for Auth Security Model.

Merges fine-tuned / reinforced LoRA adapter weights directly into the base
Qwen2.5-Coder architecture to produce a standalone full-precision model artifact.
"""

import argparse
import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# PEFT torchao workaround for Windows / Kaggle
try:
    import peft.import_utils
    peft.import_utils.is_torchao_available = lambda: False
    if hasattr(peft.import_utils, "is_torch_ao_available"):
        peft.import_utils.is_torch_ao_available = lambda: False
    import peft.tuners.lora.torchao
    peft.tuners.lora.torchao.dispatch_torchao = lambda *args, **kwargs: None
    peft.tuners.lora.torchao.is_torchao_available = lambda: False
except Exception:
    pass

from peft import PeftModel


def merge_lora_to_base(
    base_model_id: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
    adapter_path: str = "checkpoints_1.5b/final_adapter",
    output_dir: str = "checkpoints/merged_model",
    device: str = "auto",
):
    print("=" * 80)
    print("  MERGING LORA ADAPTER INTO BASE MODEL WEIGHTS")
    print(f"  • Base Model:   {base_model_id}")
    print(f"  • Adapter Path: {adapter_path}")
    print(f"  • Output Dir:   {output_dir}")
    print("=" * 80)

    if not os.path.exists(adapter_path):
        raise FileNotFoundError(f"Adapter path not found: {adapter_path}")

    start_time = time.time()
    os.makedirs(output_dir, exist_ok=True)

    print("\n[1/4] Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(adapter_path, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print("[2/4] Loading base model in float16...")
    dtype = torch.float16 if torch.cuda.is_available() else torch.float32
    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        torch_dtype=dtype,
        device_map=device if torch.cuda.is_available() else None,
        trust_remote_code=True,
    )

    print("[3/4] Attaching LoRA adapter and fusing weights (merge_and_unload)...")
    peft_model = PeftModel.from_pretrained(base_model, adapter_path)
    merged_model = peft_model.merge_and_unload()

    print(f"[4/4] Saving fused standalone model to: {output_dir}...")
    merged_model.save_pretrained(output_dir, safe_serialization=True)
    tokenizer.save_pretrained(output_dir)

    elapsed = time.time() - start_time
    print(f"\n[OK] Model successfully merged and saved in {elapsed:.2f}s!")
    print(f"     Destination: {output_dir}")
    print("=" * 80)
    return output_dir


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Merge LoRA weights into base model")
    parser.add_argument("--base_model_id", type=str, default="Qwen/Qwen2.5-Coder-1.5B-Instruct")
    parser.add_argument("--adapter_path", type=str, default="checkpoints_1.5b/final_adapter")
    parser.add_argument("--output_dir", type=str, default="checkpoints/merged_model")
    parser.add_argument("--device", type=str, default="auto")
    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    merge_lora_to_base(
        base_model_id=args.base_model_id,
        adapter_path=args.adapter_path,
        output_dir=args.output_dir,
        device=args.device,
    )
