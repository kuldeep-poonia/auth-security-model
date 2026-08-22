import os
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

import argparse
import glob
import json
import re
import sys
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import torch
from torch.utils.data import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
    DataCollatorForSeq2Seq,
)

# Complete torchao bypass for PEFT in all environments (Kaggle/Colab/Codespace)
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


class SecurityDataset(Dataset):
    """PyTorch Dataset that formats multi-turn chat records with prompt masking (-100 labels).

    Guarantees:
    1. len(input_ids) <= max_length (strictly enforced for every sample).
    2. assistant JSON tokens are preserved and capped to max 128 tokens.
    3. 100% of samples have valid supervised tokens (0 NaNs).
    """

    def __init__(self, formatted_items: List[Dict[str, Any]], tokenizer: Any, max_length: int = 384):
        self.examples = []
        for item in formatted_items:
            messages = item["messages"]
            system_msg = messages[0]["content"]
            user_msg = messages[1]["content"]
            assistant_msg = messages[2]["content"]

            context_messages = [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ]

            if hasattr(tokenizer, "apply_chat_template"):
                context_text = tokenizer.apply_chat_template(context_messages, tokenize=False, add_generation_prompt=True)
            else:
                context_text = f"<|im_start|>system\n{system_msg}<|im_end|>\n<|im_start|>user\n{user_msg}<|im_end|>\n<|im_start|>assistant\n"

            assistant_text = f"{assistant_msg}<|im_end|>\n"

            # Tokenize assistant response capped to max 128 tokens
            assistant_tokens = tokenizer(assistant_text, truncation=True, max_length=128, add_special_tokens=False)["input_ids"]
            if not assistant_tokens:
                assistant_tokens = tokenizer(assistant_msg, truncation=True, max_length=128, add_special_tokens=False)["input_ids"]
            assistant_len = len(assistant_tokens)

            # Max allowed tokens for context
            max_context_len = max(max_length - assistant_len, 32)

            # Tokenize context with truncation
            context_tokens = tokenizer(context_text, truncation=True, max_length=max_context_len, add_special_tokens=False)["input_ids"]

            # Combined sequence strictly capped at max_length
            input_ids = (context_tokens + assistant_tokens)[:max_length]
            context_len = len(context_tokens)

            # Mask context tokens with -100, ensure assistant tokens have real label IDs
            labels = ([-100] * context_len + list(assistant_tokens))[:len(input_ids)]
            attention_mask = [1] * len(input_ids)

            # Strict validation
            assert len(input_ids) == len(labels) == len(attention_mask) <= max_length
            assert any(l != -100 for l in labels), "Record must have supervised labels"

            is_vuln = bool(item.get("is_vulnerable", False) or ('"is_vulnerable": true' in assistant_msg.lower()))

            self.examples.append({
                "input_ids": input_ids,
                "attention_mask": attention_mask,
                "labels": labels,
                "is_vulnerable": 1.0 if is_vuln else 0.0,
            })

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        return self.examples[idx]


class WeightedTrainer(Trainer):
    """Custom Trainer implementing mathematically exact per-sample class-weighted cross-entropy loss."""

    def __init__(self, *args, vuln_loss_weight: float = 1.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.vuln_loss_weight = vuln_loss_weight

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        is_vuln_list = inputs.pop("is_vulnerable", None)
        labels = inputs.get("labels")
        outputs = model(**inputs)

        if is_vuln_list is not None and self.vuln_loss_weight != 1.0 and labels is not None and hasattr(outputs, "logits") and outputs.logits is not None:
            logits = outputs.logits
            shift_logits = logits[..., :-1, :].contiguous()
            shift_labels = labels[..., 1:].contiguous()

            # Exact per-token cross entropy with ignore_index=-100
            loss_fct = torch.nn.CrossEntropyLoss(reduction="none", ignore_index=-100)
            token_loss = loss_fct(shift_logits.view(-1, shift_logits.size(-1)), shift_labels.view(-1)).view(shift_labels.size())

            # Mask out un-supervised prompt tokens (-100)
            valid_mask = (shift_labels != -100).float()
            per_sample_loss = (token_loss * valid_mask).sum(dim=-1) / (valid_mask.sum(dim=-1) + 1e-8)

            # Apply exact per-sample class weights (no cross-sample dilution)
            if not isinstance(is_vuln_list, torch.Tensor):
                is_vuln_tensor = torch.tensor(is_vuln_list, device=logits.device, dtype=torch.float32)
            else:
                is_vuln_tensor = is_vuln_list.to(logits.device)
            sample_weights = torch.where(is_vuln_tensor > 0.5, self.vuln_loss_weight, 1.0)
            loss = (per_sample_loss * sample_weights).mean()
        else:
            loss = outputs.get("loss") if isinstance(outputs, dict) else outputs.loss

        return (loss, outputs) if return_outputs else loss


def train(args):
    import gc
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

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

    real_cnt = sum(1 for r in train_items if "hardcore_validated_synthetic" not in str(r.get("source", "")))
    synth_cnt = len(train_items) - real_cnt
    vuln_cnt = sum(1 for r in train_items if bool(r.get("is_vulnerable", False) or ('"is_vulnerable": true' in r["messages"][2]["content"].lower())))
    clean_cnt = len(train_items) - vuln_cnt

    print("=" * 75)
    print(f"[DATASET] Total Training Examples: {len(train_items)} (Real: {real_cnt}, Synthetic: {synth_cnt})")
    print(f"[DATASET] Class Balance: {vuln_cnt} Vulnerable ({vuln_cnt/len(train_items)*100:.1f}%) | {clean_cnt} Clean ({clean_cnt/len(train_items)*100:.1f}%)")
    print(f"[CONFIG] Detected GPUs: {torch.cuda.device_count() if torch.cuda.is_available() else 0}")
    print(f"[CONFIG] Vulnerable Loss Weight: {args.vuln_loss_weight}x")
    print(f"[CONFIG] Train dataset tokens size: {len(train_dataset)}, Val: {len(val_dataset) if val_dataset else 0}")
    print("=" * 75)

    os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

    # Configure Model Loading
    device_map = {"": 0} if torch.cuda.is_available() else None
    torch_dtype = torch.float16 if torch.cuda.is_available() else torch.float32

    use_4bit = args.use_qlora or args.load_in_4bit
    if not use_4bit and "3b" in args.model_id.lower() and torch.cuda.is_available():
        # Auto-enable 4-bit QLoRA on 3B+ models to ensure safe headroom on 16GB GPUs
        use_4bit = True
        print("[INFO] Auto-enabling 4-Bit NF4 QLoRA for 3B model to guarantee <5GB VRAM usage on T4 GPU.")

    if use_4bit and torch.cuda.is_available():
        from transformers import BitsAndBytesConfig
        from peft import prepare_model_for_kbit_training

        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
        print(f"[INFO] Loading base model in 4-Bit NF4 QLoRA: {args.model_id} (weight memory: ~1.8 GB)")
        model = AutoModelForCausalLM.from_pretrained(
            args.model_id,
            quantization_config=bnb_config,
            device_map=device_map,
            trust_remote_code=True,
        )
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    else:
        print(f"[INFO] Loading base model in native FP16: {args.model_id}")
        model = AutoModelForCausalLM.from_pretrained(
            args.model_id,
            torch_dtype=torch_dtype,
            device_map=device_map,
            trust_remote_code=True,
        )
    model.config.use_cache = False

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
    model.config.use_cache = False
    if hasattr(model, "base_model"):
        model.base_model.config.use_cache = False

    # Prevent Trainer from wrapping in torch.nn.DataParallel on multi-GPU systems (incompatible with bitsandbytes 4-bit)
    if torch.cuda.is_available():
        model.is_parallelizable = True
        model.model_parallel = True
    if hasattr(model, "base_model"):
        model.base_model.config.use_cache = False

    if torch.cuda.is_available():
        model.enable_input_require_grads()
        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        print("[OK] use_cache explicitly disabled: False")
        print("[OK] Non-reentrant gradient checkpointing enabled on model")
        print(f"[OK] PYTORCH_CUDA_ALLOC_CONF: {os.environ.get('PYTORCH_CUDA_ALLOC_CONF')}")

    model.print_trainable_parameters()

    # Construct TrainingArguments safely across transformers versions
    import inspect
    sig = inspect.signature(TrainingArguments.__init__).parameters
    training_kwargs = {
        "output_dir": target_dir,
        "per_device_train_batch_size": args.batch_size,
        "per_device_eval_batch_size": 2,
        "gradient_accumulation_steps": args.gradient_accumulation_steps,
        "learning_rate": args.learning_rate,
        "lr_scheduler_type": "cosine",
        "weight_decay": 0.01,
        "num_train_epochs": args.epochs if not args.smoke_test else 1,
        "max_steps": args.max_steps if (args.max_steps and args.max_steps > 0) else -1,
        "logging_steps": 1 if args.smoke_test else 10,
        "save_strategy": "steps",
        "save_steps": args.save_steps,
        "save_total_limit": 5,
        "load_best_model_at_end": True if (val_dataset and not args.smoke_test) else False,
        "metric_for_best_model": "eval_f1" if (val_dataset and not args.smoke_test) else "eval_loss",
        "greater_is_better": True if (val_dataset and not args.smoke_test) else False,
        "fp16": torch.cuda.is_available(),
        "bf16": False,
        "gradient_checkpointing": True if torch.cuda.is_available() else False,
        "gradient_checkpointing_kwargs": {"use_reentrant": False} if ("gradient_checkpointing_kwargs" in sig and torch.cuda.is_available()) else None,
        "report_to": "none",
        "dataloader_num_workers": 0,
        "dataloader_pin_memory": torch.cuda.is_available(),
    }
    training_kwargs = {k: v for k, v in training_kwargs.items() if v is not None}

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

    def preprocess_logits_for_metrics(logits, labels):
        if isinstance(logits, tuple):
            logits = logits[0]
        return logits.argmax(dim=-1)

    def compute_metrics(eval_pred):
        predictions, labels = eval_pred
        true_pos, false_pos, true_neg, false_neg = 0, 0, 0, 0

        for pred_ids, label_ids in zip(predictions, labels):
            mask = (label_ids != -100)
            if not mask.any():
                continue
            target_text = tokenizer.decode(label_ids[mask], skip_special_tokens=True).lower()
            pred_text = tokenizer.decode(pred_ids[mask], skip_special_tokens=True).lower()

            is_true_vuln = ('"vulnerable": true' in target_text or '"is_vulnerable": true' in target_text)
            is_pred_vuln = ('"vulnerable": true' in pred_text or '"is_vulnerable": true' in pred_text)

            if is_true_vuln and is_pred_vuln:
                true_pos += 1
            elif not is_true_vuln and is_pred_vuln:
                false_pos += 1
            elif not is_true_vuln and not is_pred_vuln:
                true_neg += 1
            else:
                false_neg += 1

        prec = true_pos / (true_pos + false_pos) if (true_pos + false_pos) > 0 else 0.0
        rec = true_pos / (true_pos + false_neg) if (true_pos + false_neg) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        total = true_pos + false_pos + true_neg + false_neg
        acc = (true_pos + true_neg) / total if total > 0 else 0.0
        spec = true_neg / (true_neg + false_pos) if (true_neg + false_pos) > 0 else 0.0

        return {
            "f1": round(f1, 4),
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "specificity": round(spec, 4),
        }

    from transformers import TrainerCallback, EarlyStoppingCallback
    class EvalLoggingCallback(TrainerCallback):
        def on_evaluate(self, args, state, control, metrics=None, **kwargs):
            if metrics:
                step = state.global_step
                loss = metrics.get("eval_loss", 0.0)
                f1 = metrics.get("eval_f1", 0.0)
                acc = metrics.get("eval_accuracy", 0.0) * 100
                rec = metrics.get("eval_recall", 0.0) * 100
                prec = metrics.get("eval_precision", 0.0) * 100
                spec = metrics.get("eval_specificity", 0.0) * 100
                print(
                    f"\n[EVAL STEP {step}] eval_loss: {loss:.4f} | eval_f1: {f1:.4f} | "
                    f"eval_rec: {rec:.1f}% | eval_prec: {prec:.1f}% | eval_spec: {spec:.1f}% | eval_acc: {acc:.1f}%\n",
                    flush=True,
                )

    callbacks = [EvalLoggingCallback()]
    if val_dataset and not args.smoke_test:
        callbacks.append(EarlyStoppingCallback(early_stopping_patience=6, early_stopping_threshold=0.001))

    # Initialize WeightedTrainer with class-weighted loss support
    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        data_collator=DataCollatorForSeq2Seq(tokenizer=tokenizer, pad_to_multiple_of=8, return_tensors="pt", padding=True),
        compute_metrics=compute_metrics if (val_dataset and not args.smoke_test) else None,
        preprocess_logits_for_metrics=preprocess_logits_for_metrics if (val_dataset and not args.smoke_test) else None,
        callbacks=callbacks,
        vuln_loss_weight=args.vuln_loss_weight,
    )

    latest_ckpt = find_latest_checkpoint(target_dir) if args.resume else None
    if args.resume and latest_ckpt:
        print(f"[INFO] Resuming training from checkpoint: {latest_ckpt}")
        logger.log_event("resume", {"checkpoint": latest_ckpt})
        train_result = trainer.train(resume_from_checkpoint=latest_ckpt)
    else:
        print("[INFO] Starting training from scratch...")
        train_result = trainer.train()

    # Save final model adapter and tokenizer (Trainer reloads best model when load_best_model_at_end=True)
    best_ckpt = getattr(trainer.state, "best_model_checkpoint", None)
    best_metric = getattr(trainer.state, "best_metric", None)
    if best_ckpt:
        print(f"[OK] Best model loaded from: {best_ckpt} (best eval_f1: {best_metric:.4f})")

    final_adapter_dir = os.path.join(target_dir, "final_adapter")
    trainer.save_model(final_adapter_dir)
    tokenizer.save_pretrained(final_adapter_dir)

    metrics = train_result.metrics
    if best_ckpt:
        metrics["best_model_checkpoint"] = best_ckpt
        metrics["best_eval_loss"] = best_metric
    logger.log_event("train_complete", metrics)
    print(f"[OK] Fine-tuning finished! Best adapter saved to {final_adapter_dir}")
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
        default=1,
        help="Batch size per device",
    )
    parser.add_argument(
        "--gradient_accumulation_steps",
        type=int,
        default=16,
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
        default=25,
        help="Checkpoint save interval in steps",
    )
    parser.add_argument(
        "--eval_steps",
        type=int,
        default=25,
        help="Evaluation interval in steps",
    )
    parser.add_argument(
        "--max_length",
        type=int,
        default=384,
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
        "--vuln_loss_weight",
        type=float,
        default=3.7,
        help="Loss weight multiplier for vulnerable examples to compensate for class imbalance (default: 3.7)",
    )
    parser.add_argument(
        "--smoke_test",
        action="store_true",
        help="Run a 2-step plumbing check on a 10-item subset",
    )
    parser.add_argument(
        "--use_qlora",
        action="store_true",
        help="Load base model in 4-bit NF4 quantized mode (QLoRA)",
    )
    parser.add_argument(
        "--load_in_4bit",
        action="store_true",
        help="Alias for --use_qlora",
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
